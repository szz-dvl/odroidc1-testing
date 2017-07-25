#include "cryptotest.h"

static const char * to_alg_name ( tjob * job ) {

	switch (job->tmode) {
	case CRYPTO_AES_CBC:
		return "cbc(aes)-hw";
	case CRYPTO_AES_ECB:
		return "ecb(aes)-hw";
	case CRYPTO_AES_CTR:
		return "ctr(aes)-hw";
	default:
		return "bad_alg.";
	}
}

static void aes_encrypt_cb (struct crypto_async_request *req, int err) {

	tjob * job = req->data;
	skcip_d * spec_data = job->data->spec;
	struct ablkcipher_request * myreq = &spec_data->ereq->creq;
	//uint i = 0;

	pr_info("%u >> AES encrypt finished.\n", job->id);
	
	if (verbose >= 2) {
		
		pr_info("%u >> Original text: %s \n", job->id, (char *) sg_virt(myreq->src));
		pr_info("%u >> Encrypted text: %s \n", job->id, (char *) sg_virt(myreq->dst));

		/* for (i = 0; i < job->data->txtlen; i++) */
		/* 	pr_info("%d", *(char *)(sg_virt(spec_data->ereq->creq.dst) + i)); */
		
	}

	if (job->args > 1)
		do_aes_decrypt (job);
	
}

static void  aes_decrypt_cb (struct crypto_async_request *req, int err) {

	tjob * job = req->data;
    skcip_d * spec_data = job->data->spec;
	
    pr_info("%u >> AES decrypt finished.\n", job->id);

	if (verbose >= 2) {
		pr_info("%u >> Original text: %s.\n", job->id, (char *) sg_virt(spec_data->dreq->creq.src));
		pr_info("%u >> Decrypted text: %s.\n", job->id, (char *) sg_virt(spec_data->dreq->creq.dst));
	}

	if (memcmp(sg_virt(spec_data->dreq->creq.dst), sg_virt(spec_data->ereq->creq.src), job->data->txtlen))
		pr_err("%u >> Text failed to process.\n", job->id);
	else
		pr_warn("%u >> Text successfully processed!\n", job->id);
	
	dma_free_coherent(NULL, job->data->txtlen, sg_virt(spec_data->dreq->creq.src), sg_dma_address(spec_data->dreq->creq.src));
	dma_free_coherent(NULL, job->data->txtlen, sg_virt(spec_data->dreq->creq.dst), sg_dma_address(spec_data->dreq->creq.dst));
	dma_free_coherent(NULL, job->data->txtlen, sg_virt(spec_data->ereq->creq.src), sg_dma_address(spec_data->ereq->creq.src));

	skcipher_givcrypt_free (spec_data->ereq);
    skcipher_givcrypt_free (spec_data->dreq);

	crypto_free_ablkcipher (spec_data->tfm);
	
	destroy_job(job);
	
}

static bool sg_dma_map ( tjob * job, struct scatterlist * sg ) {

	sg_set_buf(sg, dma_alloc_coherent(NULL,
									  job->data->txtlen,
									  &sg_dma_address(sg),
									  GFP_KERNEL),
			   job->data->txtlen);
	
	if (dma_mapping_error(NULL, sg_dma_address(sg))) {
		
		pr_info("%u >> Dma allocation failed (%p, 0x%08x).\n", job->id, sg_virt(sg), sg_dma_address(sg));
	    return false;
		
	} else
		sg_mark_end(sg); /* Future chain */

	return true;
}

bool do_aes_encrypt ( tjob * job ) {

	struct scatterlist * dst, * src;
	skcip_d * spec_data;

	if (!valid_state(job)) 
		return false;
	
	job->data->spec = (skcip_d *) kzalloc(sizeof(ablk_d), GFP_KERNEL);
	if (!job->data->spec)
	    return false;

	spec_data = job->data->spec;
	
	dst = &spec_data->edst;
	src = &spec_data->esrc;
	
	job->data->txtlen = ALIGN(job->data->txtlen, AES_BLOCK_SIZE);
	
	if(!crypto_has_alg(to_alg_name(job), CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC, CRYPTO_ALG_TYPE_MASK)) { //CRYPTO_ALG_TYPE_GIVCIPHER | CRYPTO_ALG_GENIV | 
		
		pr_err("%u >> Algorithm not found, aborting.\n", job->id);
		return false;		
	}
	
	spec_data->tfm = __crypto_ablkcipher_cast(crypto_alloc_base(to_alg_name(job), CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC, CRYPTO_ALG_TYPE_MASK)); //CRYPTO_ALG_GENIV | CRYPTO_ALG_TYPE_GIVCIPHER | 
	if (!spec_data->tfm)
		goto fail;

	pr_info( "%u >> Algo name: %s, Driver name: %s.\n", job->id, crypto_tfm_alg_name(crypto_ablkcipher_tfm(spec_data->tfm)),
			 crypto_tfm_alg_driver_name(crypto_ablkcipher_tfm(spec_data->tfm)) );

	if (crypto_ablkcipher_setkey(spec_data->tfm, (const u8 *) job->data->key, job->data->keylen)) {
		
		pr_err("%u >> Failed to set key.\n", job->id);
	    goto fail;
	}

    spec_data->ereq = skcipher_givcrypt_alloc (spec_data->tfm, GFP_KERNEL);
	if (!spec_data->ereq)
		goto fail;

	skcipher_givcrypt_set_giv (spec_data->ereq, kzalloc(KEY_SIZE_MAX, GFP_KERNEL), 0);
	
	if (!spec_data->ereq->giv)
		goto fail;

	/* pr_warn("%u >> IV allocated.\n", job->id); */

	/* struct crypto_ablkcipher * x = skcipher_givcrypt_reqtfm(spec_data->ereq); */
	/* if(!x) */
	/* 	pr_err("%u >> NO x!\n", job->id); */
	/* else */
	/* 	pr_warn("%u >> x!\n", job->id); */
	
	/* struct ablkcipher_tfm *crt = crypto_ablkcipher_crt(x); */
	/* if(!crt) */
	/* 	pr_err("%u >> NO crt!\n", job->id); */
	/* else */
	/* 	pr_warn("%u >> crt!\n", job->id); */

	/* if (!crt->givencrypt) */
	/* 	pr_err("%u >> NO givencrypt!\n", job->id); */
	
	/* if(crt->givencrypt(spec_data->ereq)) { */
	
	/* if (crypto_skcipher_givencrypt (spec_data->ereq)) { */
		
	/* 	pr_err("%u >> Failed to generate IVs.\n", job->id); */
	/* 	goto fail; */
		
	/* } else { */
		
	/* 	pr_err("%u >> IV_0: %u, IV_1: %u, IV_2: %u, IV_3: %u.\n", job->id, */
	/* 		   ((u32 *) spec_data->ereq->giv)[0], */
	/* 		   ((u32 *) spec_data->ereq->giv)[1], */
	/* 		   ((u32 *) spec_data->ereq->giv)[2], */
	/* 		   ((u32 *) spec_data->ereq->giv)[3]); */
	/* } */

	
	if (sg_dma_map(job, src)) 
		memcpy(sg_virt(src), job->data->text, job->data->txtlen);
	else
		goto fail;

	if (sg_dma_map(job, dst)) 
		memset(sg_virt(dst),0, job->data->txtlen);
	else
		goto fail;
	
    skcipher_givcrypt_set_crypt (spec_data->ereq, src, dst, job->data->txtlen, NULL);
	
	pr_info("%u >> AES encrypt ready, src: (%p, 0x%08x), dst: (%p, 0x%08x).\n", job->id,
			sg_virt(spec_data->ereq->creq.src), sg_dma_address(spec_data->ereq->creq.src),
			sg_virt(spec_data->ereq->creq.dst), sg_dma_address(spec_data->ereq->creq.dst));
	
    skcipher_givcrypt_set_callback (spec_data->ereq, 0, aes_encrypt_cb, job);
	
	if (crypto_ablkcipher_encrypt(&spec_data->ereq->creq) < 0)
	    goto fail;
	
	return true;
	
 fail:
	pr_err("%u >> Configuration error.\n", job->id);
	
	if (spec_data->tfm)
		crypto_free_ablkcipher (spec_data->tfm);

	if (spec_data->ereq)
		skcipher_givcrypt_free (spec_data->ereq);
	
	if (sg_virt(src))
		dma_free_coherent(NULL, job->data->txtlen, sg_virt(src), sg_dma_address(src));
	
	if (sg_virt(dst))
		dma_free_coherent(NULL, job->data->txtlen, sg_virt(dst), sg_dma_address(dst));
	
	destroy_job(job);

	return false;
}

bool do_aes_decrypt ( tjob * job ) {

    skcip_d * spec_data = job->data->spec;
	struct scatterlist * dst;

	dst = &spec_data->ddst;
	
	if (crypto_ablkcipher_setkey(spec_data->tfm, (const u8 *) job->data->key, job->data->keylen)) {
		
		pr_err("%u >> Failed to set key.\n", job->id);
		return false;
		
	}

    spec_data->dreq = skcipher_givcrypt_alloc (spec_data->tfm, GFP_KERNEL);
	if (!spec_data->dreq)
		goto fail;

	skcipher_givcrypt_set_giv (spec_data->dreq, spec_data->ereq->giv, 0);

	/* if (crypto_skcipher_givdecrypt (spec_data->ereq)) { */
		
	/* 	pr_err("%u >> Failed to generate IVs.\n", job->id); */
	/* 	goto fail; */
		
	/* } else { */
		
	/* 	pr_err("%u >> IV_0: %u, IV_1: %u, IV_2: %u, IV_3: %u.\n", job->id, */
	/* 		   ((u32 *) spec_data->dreq->giv)[0], */
	/* 		   ((u32 *) spec_data->dreq->giv)[1], */
	/* 		   ((u32 *) spec_data->dreq->giv)[2], */
	/* 		   ((u32 *) spec_data->dreq->giv)[3]); */
	/* } */
	
	if (sg_dma_map(job, dst))
	    memset(sg_virt(dst),0, job->data->txtlen);
	else
		goto fail;

	skcipher_givcrypt_set_crypt (spec_data->dreq, spec_data->ereq->creq.dst, dst, job->data->txtlen, NULL);

	pr_info("%u >> AES decrypt ready, src: (%p, 0x%08x), dst: (%p, 0x%08x).\n", job->id,
			sg_virt(spec_data->dreq->creq.src), sg_dma_address(spec_data->dreq->creq.src),
			sg_virt(spec_data->dreq->creq.dst), sg_dma_address(spec_data->dreq->creq.dst));
	
	skcipher_givcrypt_set_callback (spec_data->dreq, 0, aes_decrypt_cb, job);
	
	
	if (crypto_ablkcipher_decrypt(&spec_data->dreq->creq) < 0)
		goto fail;
	
	return true;

 fail:	
	pr_err("%u >> Configuration error.\n", job->id);

	if (spec_data->dreq)
	    skcipher_givcrypt_free (spec_data->dreq);

	if (sg_virt(dst))
		dma_free_coherent(NULL, job->data->txtlen, sg_virt(dst), sg_dma_address(dst));
	
	return false;
}

bool do_aes ( tjob * job ) {

	if ( !do_aes_encrypt( job ))
		return false;
	
	return true;
}
