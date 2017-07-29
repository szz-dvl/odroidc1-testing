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
	struct scatterlist * src = myreq->src, * dst = myreq->dst;
	text * txt;
	
	pr_info("%u >> AES encrypt finished.\n", job->id);
	
	if (verbose >= 2) {

		list_for_each_entry (txt, &job->data->texts, elem) {

			print_hex_dump_bytes("Encrypted text: ", DUMP_PREFIX_ADDRESS, sg_virt(dst), txt->len);
			pr_info("Original text: %s \n\n", (char *) sg_virt(src));
			src = sg_next(src);
		    dst = sg_next(dst);
			
		}
	}

	if (job->args > 1)
		do_aes_decrypt (job);
	
}

static void  aes_decrypt_cb (struct crypto_async_request *req, int err) {

	tjob * job = req->data;
    skcip_d * spec_data = job->data->spec;
	struct ablkcipher_request * ereq = &spec_data->ereq->creq;
	struct ablkcipher_request * dreq = &spec_data->dreq->creq;
	struct scatterlist * src = dreq->src, * dst = dreq->dst, * orig = ereq->src;
	uint len = dreq->nbytes;
	text * txt;
	bool ok = true;
	
	
    pr_info("%u >> AES decrypt finished.\n", job->id);
	
	list_for_each_entry (txt, &job->data->texts, elem) {
		
		if (memcmp(sg_virt(orig), sg_virt(dst), min(txt->len, len))) {

			if (verbose >= 2) {
		
				print_hex_dump_bytes("Encrypted text: ", DUMP_PREFIX_ADDRESS, sg_virt(src), txt->len);
				print_hex_dump_bytes("Decrypted text: ", DUMP_PREFIX_ADDRESS, sg_virt(dst), txt->len);
				print_hex_dump_bytes("Original text:  ", DUMP_PREFIX_ADDRESS, sg_virt(orig), txt->len);

				pr_err("%u >> Text %u failed to process.\n\n", job->id, txt->id);
			}

			ok = false;

		} else {

			if (verbose >= 2) {
		
				print_hex_dump_bytes("Encrypted text: ", DUMP_PREFIX_ADDRESS, sg_virt(src), txt->len);
				pr_info("Decrypted text: %s\n", (char *) sg_virt(dst));

				pr_warn("%u >> Text %u successfully processed!\n\n", job->id, txt->id);
			}
		}
		
		if (!ok)
			break;

		len -= sg_dma_len(orig);
		
		src = sg_next(src);
	    dst = sg_next(dst);
		orig = sg_next(orig);	
	}
	
	if (ok)
		pr_warn("%u >> Texts successfully processed!\n", job->id);
	else
		pr_err("%u >> Texts failed to process.\n", job->id);
		
	destroy_job(job);
}

static bool sg_dma_map ( tjob * job, struct scatterlist * sg, uint len) {
	
	sg_set_buf(sg, dma_alloc_coherent(NULL,
									  len,
									  &sg_dma_address(sg),
									  GFP_ATOMIC),
			   len);
	
	if (dma_mapping_error(NULL, sg_dma_address(sg))) {
		
		pr_err("%u >> Dma allocation failed (%p, 0x%08x).\n", job->id, sg_virt(sg), sg_dma_address(sg));
	    return false;
		
	} 
	
	return true;
}

static bool job_map_text ( tjob * job, text * txt, struct scatterlist * src, struct scatterlist * dst ) {
	
	skcip_d * spec_data = job->data->spec;
	
	txt->len = ALIGN(txt->len, crypto_ablkcipher_alignmask(spec_data->tfm) + 1);

	if (sg_dma_map(job, src, txt->len)) 
		memcpy(sg_virt(src), txt->text, txt->len);
	else
	    return false;

	if (sg_dma_map(job, dst, txt->len)) 
		memset(sg_virt(dst),0, txt->len);
	else
	    return false;

	return true;
}

static bool job_map_texts ( tjob * job ) {

	skcip_d * spec_data = job->data->spec;
	struct scatterlist * dst, * src;
	text * txt;
	
	if (sg_alloc_table(&spec_data->edst, job->data->text_num, GFP_KERNEL))
	    return false;
	
	if (sg_alloc_table(&spec_data->esrc, job->data->text_num, GFP_KERNEL))
		return false;
	
	dst = spec_data->edst.sgl;
	src = spec_data->esrc.sgl;

	list_for_each_entry (txt, &job->data->texts, elem) {
		
		if (!job_map_text (job, txt, src, dst))
			return false;

		dst = sg_next(dst);
		src = sg_next(src);

	}
	
	return true;
}

bool do_aes_encrypt ( tjob * job ) {

	skcip_d * spec_data;
	u32 type = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC;

	if (job->tmode)
		type |= CRYPTO_ALG_TYPE_GIVCIPHER;
	
	spec_data = job->data->spec = (skcip_d *) kzalloc(sizeof(skcip_d), GFP_KERNEL);
	if (!spec_data)
	    goto fail;
	
	if(!crypto_has_alg(to_alg_name(job), type, CRYPTO_ALG_TYPE_MASK)) {
		
		pr_err("%u >> Algorithm not found, aborting.\n", job->id);
	    goto fail;		
	}
	
	spec_data->tfm = __crypto_ablkcipher_cast(crypto_alloc_base(to_alg_name(job), type, CRYPTO_ALG_TYPE_MASK));
	if (!spec_data->tfm)
		goto fail;

	job->data->nbytes = ALIGN(job->data->nbytes, crypto_ablkcipher_alignmask(spec_data->tfm) + 1);
	
	pr_info( "%u >> Algo name: %s, Driver name: %s.\n", job->id, crypto_tfm_alg_name(crypto_ablkcipher_tfm(spec_data->tfm)),
			 crypto_tfm_alg_driver_name(crypto_ablkcipher_tfm(spec_data->tfm)) );
	
	if (crypto_ablkcipher_setkey(spec_data->tfm, (const u8 *) job->data->key, job->data->keylen)) {
		
		pr_err("%u >> Failed to set key.\n", job->id);
	    goto fail;
	}

    spec_data->ereq = skcipher_givcrypt_alloc (spec_data->tfm, GFP_KERNEL);
	if (!spec_data->ereq)
		goto fail;

	if (job->tmode) {

		skcipher_givcrypt_set_giv (spec_data->ereq, kzalloc(crypto_ablkcipher_crt(spec_data->tfm)->ivsize, GFP_KERNEL), 0);

		if (!spec_data->ereq->giv) {

			pr_err("%u >> Failed to generate IVs.\n", job->id);
			goto fail;
			
		}
	}

	if (!job_map_texts(job))
		goto fail;
	
    skcipher_givcrypt_set_crypt (spec_data->ereq, spec_data->esrc.sgl, spec_data->edst.sgl, job->data->nbytes, NULL);
	
	pr_info("%u >> AES encrypt ready, src: (%p, 0x%08x), dst: (%p, 0x%08x).\n", job->id,
			sg_virt(spec_data->ereq->creq.src), sg_dma_address(spec_data->ereq->creq.src),
			sg_virt(spec_data->ereq->creq.dst), sg_dma_address(spec_data->ereq->creq.dst));
	
    skcipher_givcrypt_set_callback (spec_data->ereq, 0, aes_encrypt_cb, job);

	if (job->tmode) {
		
		if (crypto_skcipher_givencrypt(spec_data->ereq) < 0)
			goto fail;
		
	} else {
		
		if (crypto_ablkcipher_encrypt(&spec_data->ereq->creq) < 0)
			goto fail;
	}
	
	return true;
	
 fail:
	pr_err("%u >> Configuration error.\n", job->id);
	
	destroy_job(job);
	
	return false;
}

bool do_aes_decrypt ( tjob * job ) {

    skcip_d * spec_data = job->data->spec;
	struct scatterlist * dst;
	text * txt;

	if (sg_alloc_table(&spec_data->ddst, job->data->text_num, GFP_KERNEL))
	    goto fail;
	
	dst = spec_data->ddst.sgl;
	
	if (crypto_ablkcipher_setkey(spec_data->tfm, (const u8 *) job->data->key, job->data->keylen)) {
		
		pr_err("%u >> Failed to set key.\n", job->id);
		return false;
		
	}

    spec_data->dreq = skcipher_givcrypt_alloc (spec_data->tfm, GFP_KERNEL);
	if (!spec_data->dreq)
		goto fail;

	/* skcipher_givcrypt_set_giv (spec_data->dreq, kzalloc(crypto_ablkcipher_crt(spec_data->tfm)->ivsize, GFP_KERNEL), 0); */
	/* if (!spec_data->dreq->giv) */
	/* 	goto fail; */

	if (job->tmode)
		skcipher_givcrypt_set_giv (spec_data->dreq, spec_data->ereq->giv, 0);

	list_for_each_entry (txt, &job->data->texts, elem) {
		
		if (sg_dma_map (job, dst, txt->len))
			memset(sg_virt(dst), 0, txt->len);
		else
			goto fail;

		dst = sg_next(dst);
	}
	
	skcipher_givcrypt_set_crypt (spec_data->dreq, spec_data->ereq->creq.dst, spec_data->ddst.sgl, job->data->nbytes, NULL);

	pr_info("%u >> AES decrypt ready, src: (%p, 0x%08x), dst: (%p, 0x%08x).\n", job->id,
			sg_virt(spec_data->dreq->creq.src), sg_dma_address(spec_data->dreq->creq.src),
			sg_virt(spec_data->dreq->creq.dst), sg_dma_address(spec_data->dreq->creq.dst));
	
	skcipher_givcrypt_set_callback (spec_data->dreq, 0, aes_decrypt_cb, job);
	
	if (job->tmode) {

		if (crypto_skcipher_givdecrypt(spec_data->dreq) < 0)
			goto fail;
		
	} else {
		
		if (crypto_ablkcipher_decrypt(&spec_data->dreq->creq) < 0)
			goto fail;
	}
	
	return true;

 fail:
	pr_err("%u >> Configuration error.\n", job->id);

	if (spec_data->dreq) {
		
		struct ablkcipher_request * dreq = &spec_data->dreq->creq;
		
		dst = dreq->dst;
		
		while (dst) {
				
			if (sg_dma_address(dst)) {
				
				dma_free_coherent(NULL, sg_dma_len(dst), sg_virt(dst), sg_dma_address(dst));
				dst = sg_next(dst);
				
			} else
				break;
			
		}
		
		sg_free_table(&spec_data->ddst);
		
		skcipher_givcrypt_free (spec_data->dreq);
	}
	
	return false;
}

bool do_aes ( tjob * job ) {

	if ( !do_aes_encrypt( job ))
		return false;
	
	return true;
}
