#include "cryptotest.h"

static const char * to_alg_name ( tjob * job ) {

	switch (job->tmode) {
	case CRYPTO_AES_CBC:
		return "cbc(aes)";
	case CRYPTO_AES_ECB:
		return "ecb(aes)";
	case CRYPTO_AES_CTR:
		return "ctr(aes)";
	default:
		return "bad_alg.";
	}
}

static void aes_encrypt_cb (struct crypto_async_request *req, int err) {

	tjob * job = req->data;
    ablk_d * spec_data = job->data->spec;
	
	pr_info("%u >> AES encrypt finished.\n", job->id);
	
	if (verbose >= 2) {
		
		pr_info("%u >> Original text: %s.\n", job->id, job->data->text);
		pr_info("%u >> Encrypted text: %s.\n", job->id, (char *) sg_virt(spec_data->ereq->dst));
		
	}

	if (job->args > 1)
		do_aes_decrypt (job);
	
}

static void  aes_decrypt_cb (struct crypto_async_request *req, int err) {

	tjob * job = req->data;
	ablk_d * spec_data = job->data->spec;
	
    pr_info("%u >> AES decrypt finished.\n", job->id);

	if (verbose >= 2) {
		pr_info("%u >> Original text: %s.\n", job->id, (char *) sg_virt(spec_data->dreq->src));
		pr_info("%u >> Decrypted text: %s.\n", job->id, (char *) sg_virt(spec_data->dreq->dst));
	}

	if (memcmp(sg_virt(spec_data->dreq->dst), sg_virt(spec_data->ereq->src), job->data->txtlen))
		pr_err("%u >> Text failed to process.\n", job->id);
	else
		pr_warn("%u >> Text successfully processed!\n", job->id);
	
	dma_free_coherent(NULL, job->data->txtlen, sg_virt(spec_data->dreq->src), sg_dma_address(spec_data->dreq->src));
	dma_free_coherent(NULL, job->data->txtlen * 2, sg_virt(spec_data->dreq->dst), sg_dma_address(spec_data->dreq->dst));
	dma_free_coherent(NULL, job->data->txtlen, sg_virt(spec_data->ereq->src), sg_dma_address(spec_data->ereq->src));
	
	destroy_job(job);
	
}

static bool init_aes ( tjob * job ) {

	/* struct scatterlist spec_data->esrc, edst; */
	/* struct scatterlist ddst; */
    ablk_d * spec_data = job->data->spec;
	//dma_addr_t  p_addr;
	//void * buff;
	
	if (!valid_state(job)) 
		return false;
	
	spec_data = (ablk_d *) kzalloc(sizeof(ablk_d), GFP_KERNEL);
	if (!spec_data)
	    return false;
	
	spec_data->tfm = __crypto_ablkcipher_cast(crypto_alloc_base(to_alg_name(job), CRYPTO_ALG_TYPE_ABLKCIPHER, CRYPTO_ALG_TYPE_BLKCIPHER_MASK | CRYPTO_ALG_ASYNC));
	if (!spec_data->tfm)
		goto fail;
	
    spec_data->ereq = ablkcipher_request_alloc(spec_data->tfm, GFP_KERNEL);
	if (!spec_data->ereq)
		goto fail;
	
	spec_data->dreq = ablkcipher_request_alloc(spec_data->tfm, GFP_KERNEL);
	if (!spec_data->dreq)
		goto fail;

	if (crypto_ablkcipher_setkey(spec_data->tfm, (const u8 *) job->data->key, job->data->keylen))
		goto fail; /* !!! */

	sg_set_buf(&spec_data->esrc, dma_alloc_coherent(NULL,
										 job->data->txtlen,
										 &sg_dma_address(&spec_data->esrc),
										 GFP_KERNEL),
			   job->data->txtlen);

	if (dma_mapping_error(NULL, sg_dma_address(&spec_data->esrc)))  
		goto fail;
	else {
		
		pr_info("%u >> Dma allocation success (%p, 0x%08x).\n", job->id, sg_virt(&spec_data->esrc), sg_dma_address(&spec_data->esrc));
		memcpy(sg_virt(&spec_data->esrc), job->data->text, job->data->txtlen);
		
	}
	 
	sg_set_buf(&spec_data->ddst, dma_alloc_coherent(NULL,
										  job->data->txtlen,
										  &sg_dma_address(&spec_data->ddst),
										  GFP_KERNEL),
				job->data->txtlen);
	
	if (dma_mapping_error(NULL, sg_dma_address(&spec_data->ddst))) 
		goto fail;
	else {
		pr_info("%u >> Dma allocation success (%p, 0x%08x).\n", job->id, sg_virt(&spec_data->ddst), sg_dma_address(&spec_data->ddst));
		memset(sg_virt(&spec_data->ddst), 0, job->data->txtlen);
	}
	
    sg_set_buf(&spec_data->edst, dma_alloc_coherent(NULL,
										  job->data->txtlen * 2,
										  &sg_dma_address(&spec_data->edst),
										  GFP_KERNEL),
				job->data->txtlen * 2);

	if (dma_mapping_error(NULL, sg_dma_address(&spec_data->edst))) 
		goto fail;
	else {
		pr_info("%u >> Dma allocation success (%p, 0x%08x).\n", job->id, sg_virt(&spec_data->edst), sg_dma_address(&spec_data->edst));
		memset(sg_virt(&spec_data->edst),0, job->data->txtlen * 2);
	}
	
	ablkcipher_request_set_crypt(spec_data->ereq, &spec_data->esrc, &spec_data->edst, job->data->txtlen, NULL);
	ablkcipher_request_set_crypt(spec_data->dreq, &spec_data->edst, &spec_data->ddst, job->data->txtlen * 2, NULL);
	
	ablkcipher_request_set_callback (spec_data->ereq, 0, aes_encrypt_cb, job);
	ablkcipher_request_set_callback (spec_data->dreq, 0, aes_decrypt_cb, job);
	
	return true;
	
 fail:
	pr_err("%u >> Configuration error.\n", job->id);
	
	if (spec_data->tfm)
		crypto_free_ablkcipher (spec_data->tfm);

	if (spec_data->ereq)
		ablkcipher_request_free (spec_data->ereq);

	if (spec_data->dreq)
		ablkcipher_request_free (spec_data->dreq);
	
	if (sg_virt(&spec_data->esrc))
		dma_free_coherent(NULL, job->data->txtlen, sg_virt(&spec_data->esrc), sg_dma_address(&spec_data->esrc));
	
	if (sg_virt(&spec_data->edst))
		dma_free_coherent(NULL, job->data->txtlen * 2, sg_virt(&spec_data->edst), sg_dma_address(&spec_data->edst));
	
	if (sg_virt(&spec_data->ddst))
		dma_free_coherent(NULL, job->data->txtlen, sg_virt(&spec_data->ddst), sg_dma_address(&spec_data->ddst));
	
	destroy_job(job);

	return false;
}

bool do_aes_encrypt ( tjob * job ) {

    ablk_d * spec_data;
	
	if (!init_aes(job))
		return false;

	spec_data = job->data->spec;
	pr_info("%u >> Init AES success\n", job->id);
	
	if (crypto_ablkcipher_encrypt(spec_data->ereq))
		return false;
	
	return true;
}

bool do_aes_decrypt ( tjob * job ) {

	ablk_d * spec_data = job->data->spec;
	
	if (crypto_ablkcipher_setkey(spec_data->tfm, (const u8 *) job->data->key, job->data->keylen)) {
		
		pr_err("%u >> Failed to set key.\n", job->id);
		return false;
		
	}

	if (crypto_ablkcipher_decrypt(spec_data->dreq))
		return false;
	
	return true;
}

bool do_aes ( tjob * job ) {

	if ( !do_aes_encrypt( job ))
		return false;
	
	return true;
}
