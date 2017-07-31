#include "cryptotest.h"

static const char * to_alg_name ( tjob * job ) {

	switch (job->tmode) {
	case CRYPTO_TDES_ECB:
		return "ecb(tdes)-hw";
	case CRYPTO_TDES_CBC:
		return "cbc(tdes)-hw";
	case CRYPTO_DES_ECB:
		return "ecb(des)-hw";
	case CRYPTO_DES_CBC:
		return "cbc(des)-hw";
	case CRYPTO_DDES_ECB:
		return "ecb(ddes)-hw";
	case CRYPTO_DDES_CBC:
		return "cbc(ddes)-hw";
		
	default:
		return "bad_alg.";
	}
}

static void tdes_encrypt_cb (struct crypto_async_request *req, int err) {

	tjob * job = req->data;
    ablk_d * spec_data = job->data->spec;
	struct ablkcipher_request * myreq = spec_data->ereq;
	struct scatterlist * src = myreq->src, * dst = myreq->dst;
	unsigned long diff = jiffies - job->stime;
		
	if (verbose >= 3) {
		
		sg_multi_each(src, dst) {
			
			print_hex_dump_bytes("Encrypted text: ", DUMP_PREFIX_ADDRESS, sg_virt(dst), sg_dma_len(dst));
			pr_info("Original text: %s \n", (char *) sg_virt(src));
			pr_info("\t\t |------------------------------------------------------|\n");
		}
	}
	
	pr_warn("%u >> TDES encrypt finished successfully in %u ns.\n", job->id, jiffies_to_usecs(diff));
	
	if (job->args > 1)
		do_tdes_decrypt (job);
	
}

static void  tdes_decrypt_cb (struct crypto_async_request *req, int err) {

	tjob * job = req->data;
    ablk_d * spec_data = job->data->spec;
	struct ablkcipher_request * ereq = spec_data->ereq;
	struct ablkcipher_request * dreq = spec_data->dreq;
	struct scatterlist * src = dreq->src, * dst = dreq->dst, * orig = ereq->src;
	int len = dreq->nbytes, i = 0;
	bool ok = true;
	unsigned long diff = jiffies - job->stime;
		
	sg_multi_each(src, dst) {
		
		if (memcmp(sg_virt(orig), sg_virt(dst), min(sg_dma_len(dst), (uint)len))) {

			if (verbose >= 1) {

				pr_err("%u >> Text %u failed to decrypt.\n", job->id, i);
		   
				print_hex_dump_bytes("Encrypted text: ", DUMP_PREFIX_ADDRESS, sg_virt(src), sg_dma_len(src));
				pr_info("\t\t |------------------------------------------------------|\n");
				print_hex_dump_bytes("Decrypted text: ", DUMP_PREFIX_ADDRESS, sg_virt(dst), sg_dma_len(dst));
				pr_info("\t\t |------------------------------------------------------|\n");
				print_hex_dump_bytes("Original text:  ", DUMP_PREFIX_ADDRESS, sg_virt(orig), sg_dma_len(orig));

			}
			
			ok = false;

		} else {

			if (verbose >= 2) {

				pr_info("%u >> Text %u successfully decrypted.\n", job->id, i);
				
				if (verbose >= 3) {
					
					print_hex_dump_bytes("Encrypted text: ", DUMP_PREFIX_ADDRESS, sg_virt(src), sg_dma_len(src));
					pr_info("Decrypted text: %s\n", (char *) sg_virt(dst));
					
				}
			}
		}

		len -= sg_dma_len(dst);
		
		if (!ok || len <= 0)
			break;
		
		orig = sg_next(orig);
		i++;
	}
	
	if (ok)
		pr_warn("%u >> TDES decrypt successfully finished in %u ns.\n", job->id, jiffies_to_usecs(diff));
	else
		pr_err("%u >> TDES decrypt finished with failures.\n", job->id);
	
	destroy_job(job);
}

bool do_tdes_encrypt ( tjob * job ) {
	
    ablk_d * spec_data;
	
	spec_data = job->data->spec = (ablk_d *) kzalloc(sizeof(ablk_d), GFP_KERNEL);
	if (!spec_data)
	    goto fail;
	
	if(!crypto_has_alg(to_alg_name(job), CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC, CRYPTO_ALG_TYPE_MASK)) {
		
		pr_err("%u >> Algorithm not found, aborting.\n", job->id);
	    goto fail;		
	}
	
	spec_data->tfm = __crypto_ablkcipher_cast(crypto_alloc_base(to_alg_name(job), CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC, CRYPTO_ALG_TYPE_MASK));
	if (!spec_data->tfm)
		goto fail;

	job->data->nbytes = ALIGN(job->data->nbytes, crypto_ablkcipher_alignmask(spec_data->tfm) + 1);
	
	pr_info( "%u >> Algo name: %s, Driver name: %s.\n", job->id, crypto_tfm_alg_name(crypto_ablkcipher_tfm(spec_data->tfm)),
			 crypto_tfm_alg_driver_name(crypto_ablkcipher_tfm(spec_data->tfm)) );
	
	if (crypto_ablkcipher_setkey(spec_data->tfm, (const u8 *) job->data->key, job->data->keylen)) {
		
		pr_err("%u >> Failed to set key.\n", job->id);
	    goto fail;
	}
	
    spec_data->ereq = ablkcipher_request_alloc (spec_data->tfm, GFP_KERNEL);
	if (!spec_data->ereq)
		goto fail;
	
	if (!job_map_texts(job))
		goto fail;
	
    ablkcipher_request_set_crypt (spec_data->ereq, spec_data->esrc.sgl, spec_data->edst.sgl, job->data->nbytes, NULL);
	
	pr_info("%u >> TDES encrypt ready, src: (%p, 0x%08x), dst: (%p, 0x%08x).\n", job->id,
			sg_virt(spec_data->ereq->src), sg_dma_address(spec_data->ereq->src),
			sg_virt(spec_data->ereq->dst), sg_dma_address(spec_data->ereq->dst));
	
    ablkcipher_request_set_callback (spec_data->ereq, 0, tdes_encrypt_cb, job);

	job->stime = jiffies;
	if (crypto_ablkcipher_encrypt(spec_data->ereq) < 0)
		goto fail;
	
	return true;
	
 fail:
	pr_err("%u >> Configuration error.\n", job->id);
	
	destroy_job(job);
	
	return false;
}


bool do_tdes_decrypt ( tjob * job ) {

    ablk_d * spec_data = job->data->spec;
	struct scatterlist * dst, * aux, * src = spec_data->ereq->dst;
	
	if (crypto_ablkcipher_setkey(spec_data->tfm, (const u8 *) job->data->key, job->data->keylen)) {
		
		pr_err("%u >> Failed to set key.\n", job->id);
		return false;
	}

    spec_data->dreq = ablkcipher_request_alloc (spec_data->tfm, GFP_KERNEL);
	if (!spec_data->dreq)
		goto fail;
	
	if (sg_alloc_table(&spec_data->ddst, job->data->text_num, GFP_KERNEL))
	    goto fail;
	
	dst = spec_data->ddst.sgl;
	
	sg_for_each (src, aux) {
		
		if (sg_dma_map (job, dst, sg_dma_len(aux)))
			memset(sg_virt(dst), 0, sg_dma_len(aux));
		else
			goto fail;

		dst = sg_next(dst);
	}
	
    ablkcipher_request_set_crypt (spec_data->dreq, spec_data->ereq->dst, spec_data->ddst.sgl, job->data->nbytes, NULL);

	pr_info("%u >> TDES decrypt ready, src: (%p, 0x%08x), dst: (%p, 0x%08x).\n", job->id,
			sg_virt(spec_data->dreq->src), sg_dma_address(spec_data->dreq->src),
			sg_virt(spec_data->dreq->dst), sg_dma_address(spec_data->dreq->dst));
	
    ablkcipher_request_set_callback (spec_data->dreq, 0, tdes_decrypt_cb, job);

	job->stime = jiffies;
	if (crypto_ablkcipher_decrypt(spec_data->dreq) < 0)
		goto fail;
	
	return true;

 fail:
	pr_err("%u >> Configuration error.\n", job->id);

	if (spec_data->dreq) {
		
		struct ablkcipher_request * dreq = spec_data->dreq;

		if (spec_data->ddst.nents) {

			dst = dreq->dst;
		
			while (dst) {
				
				if (sg_dma_address(dst)) {
					
					dma_free_coherent(NULL, sg_dma_len(dst), sg_virt(dst), sg_dma_address(dst));
					dst = sg_next(dst);
					
				} else
					break;
			
			}
		
			sg_free_table(&spec_data->ddst);
		}
		
	    ablkcipher_request_free (dreq);
	}
	
	return false;

}

bool do_tdes ( tjob * job ) {

    return do_tdes_encrypt( job );
	
}
