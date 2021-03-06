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
	unsigned long diff = jiffies - job->stime;
	
	if (verbose >= 3) {
		
		sg_multi_each(src, dst) {
			
			print_hex_dump_bytes("Encrypted text: ", DUMP_PREFIX_ADDRESS, sg_virt(dst), sg_dma_len(dst));
			pr_info("Original text: %s \n", (char *) sg_virt(src));
			pr_info("\t\t |------------------------------------------------------|\n");
		}
	}
	
	pr_warn("%u >> AES encrypt finished successfully in %u ns.\n", job->id, jiffies_to_usecs(diff));
	
	if (job->args > 1)
		do_aes_decrypt (job);
	
}

static void  aes_decrypt_cb (struct crypto_async_request *req, int err) {

	tjob * job = req->data;
    skcip_d * spec_data = job->data->spec;
	struct ablkcipher_request * ereq = &spec_data->ereq->creq;
	struct ablkcipher_request * dreq = &spec_data->dreq->creq;
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
		
		if (!ok || len <= 0) /* Comment out the first condition to get all the texts. */
			break;
		
		orig = sg_next(orig);
		i++;
	}
	
	if (ok)
		pr_warn("%u >> AES decrypt successfully finished in %u ns.\n", job->id, jiffies_to_usecs(diff));
	else
		pr_err("%u >> AES decrypt finished with failures.\n", job->id);
	
	destroy_job(job);
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

		skcipher_givcrypt_set_giv (spec_data->ereq, kzalloc(crypto_ablkcipher_ivsize(spec_data->tfm), GFP_KERNEL), sequence);

		if (!spec_data->ereq->giv) {

			pr_err("%u >> Failed to allocate IVs.\n", job->id);
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

	job->stime = jiffies;
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
	struct scatterlist * dst, * aux, * src = spec_data->ereq->creq.dst;
	
	if (crypto_ablkcipher_setkey(spec_data->tfm, (const u8 *) job->data->key, job->data->keylen)) {
		
		pr_err("%u >> Failed to set key.\n", job->id);
	    return false;
		
	}

    spec_data->dreq = skcipher_givcrypt_alloc (spec_data->tfm, GFP_KERNEL);
	if (!spec_data->dreq)
		goto fail;

	if (sg_alloc_table(&spec_data->ddst, job->data->text_num, GFP_KERNEL))
	    goto fail;
	
	dst = spec_data->ddst.sgl;
	
	/* skcipher_givcrypt_set_giv (spec_data->dreq, kzalloc(crypto_ablkcipher_ivsize(spec_data->tfm)), GFP_KERNEL), 0); */
	/* if (!spec_data->dreq->giv) */
	/* 	goto fail; */

	if (job->tmode)
		skcipher_givcrypt_set_giv (spec_data->dreq, spec_data->ereq->giv, sequence);
	
	sg_for_each (src, aux) {
		
		if (sg_dma_map (job, dst, sg_dma_len(aux)))
			memset(sg_virt(dst), 0, sg_dma_len(aux));
		else
			goto fail;

		dst = sg_next(dst);
	}
	
	skcipher_givcrypt_set_crypt (spec_data->dreq, spec_data->ereq->creq.dst, spec_data->ddst.sgl, job->data->nbytes, NULL);

	pr_info("%u >> AES decrypt ready, src: (%p, 0x%08x), dst: (%p, 0x%08x).\n", job->id,
			sg_virt(spec_data->dreq->creq.src), sg_dma_address(spec_data->dreq->creq.src),
			sg_virt(spec_data->dreq->creq.dst), sg_dma_address(spec_data->dreq->creq.dst));
	
	skcipher_givcrypt_set_callback (spec_data->dreq, 0, aes_decrypt_cb, job);

	job->stime = jiffies;
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
		
		skcipher_givcrypt_free (spec_data->dreq);
	}
	
	return false;
}

bool do_aes ( tjob * job ) {
	
    return do_aes_encrypt( job );
	
}
