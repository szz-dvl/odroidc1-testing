#include "cryptotest.h"
#include <mach/am_regs.h>

#define CRC_ALGNAME         "crc-16-hw"
#define RESULT_INI          AIU_CRC_CTRL

#define WR(data, addr)  *(volatile unsigned long *)(addr)=data
#define RD(addr)        *(volatile unsigned long *)(addr)

static bool is_initialized (tjob * job) {

	return job->data->spec;
	
}

static void crc_cb (struct crypto_async_request *req, int err) {

    tjob * job = req->data;
	ahash_d * spec_data = job->data->spec;
	unsigned long diff = jiffies - job->stime;
	struct ahash_request * myreq = spec_data->req;
	struct scatterlist * aux;
	uint i;
	u32 * res = (u32 *) myreq->result;

	crc_updt * updt;
				
	list_for_each_entry (updt, &spec_data->updates, elem) {

		if (verbose >= 2) {

			sg_for_each (updt->src.sgl, aux) {
				
				print_hex_dump_bytes("Content: ", DUMP_PREFIX_ADDRESS, sg_virt(aux), sg_dma_len(aux));
				pr_info("\t\t |------------------------------------------------------|\n");	
			}
		}
		
	}
	
	
	pr_warn("%u >> CRC hash finished in %u ns, result = 0x%08x (%u) - [0x%08x].\n", job->id, jiffies_to_usecs(diff), (u32) *myreq->result, (u32) *myreq->result, (u32) RD(CBUS_REG_ADDR(0x2278)) );
	
	for (i = 1; i < 13; i++)
		pr_info("%u >> CBUS (0x%04x) => (0x%08x, %5u) - (0x%08x, %5u).\n", job->id, RESULT_INI + (i - 1), res[i], res[i], (u32) RD(CBUS_REG_ADDR(RESULT_INI + (i - 1))), (u32) RD(CBUS_REG_ADDR(RESULT_INI + (i - 1))));
	
	destroy_job(job); /* In the driver CRC irq not arrived yet.. at least until now. */
}

static bool init_crc (tjob * job, bool init_drv) {

	ahash_d * spec_data;
	
	spec_data = job->data->spec = (skcip_d *) kzalloc(sizeof(skcip_d), GFP_KERNEL);
	if (!spec_data)
	    goto fail;

	INIT_LIST_HEAD(&spec_data->updates);
	
	if(!crypto_has_alg(CRC_ALGNAME, CRYPTO_ALG_TYPE_AHASH | CRYPTO_ALG_ASYNC, CRYPTO_ALG_TYPE_AHASH_MASK)) {
		
		pr_err("%u >> Algorithm not found, aborting.\n", job->id);
	    goto fail;		
	}

	spec_data->tfm = crypto_alloc_ahash(CRC_ALGNAME, CRYPTO_ALG_TYPE_AHASH | CRYPTO_ALG_ASYNC, CRYPTO_ALG_TYPE_AHASH_MASK);

	if (!spec_data->tfm)
		goto fail;

	pr_info( "%u >> Algo name: %s, Driver name: %s.\n", job->id, crypto_tfm_alg_name(crypto_ahash_tfm(spec_data->tfm)),
			 crypto_tfm_alg_driver_name(crypto_ahash_tfm(spec_data->tfm)) );
	
	spec_data->req = ahash_request_alloc(spec_data->tfm, GFP_KERNEL);
	if (!spec_data->req) {
		
		pr_err("%u >> No request, aborting.\n", job->id);
		goto fail;

	}
	
	/* spec_data->src = kmalloc(sizeof(struct scatterlist), GFP_KERNEL); */
	
	/* if (!spec_data->src) { */

	/* 	pr_err("%u >> No src, aborting.\n", job->id); */
	/* 	goto fail; */
		
	/* } */
	
	ahash_request_set_callback(spec_data->req, 0, crc_cb, job);
	
	if (init_drv) {
		
		if (crypto_ahash_init(spec_data->req))
			goto fail;
	}

	
	return true;

 fail:
	pr_err("%u >> Configuration error.\n", job->id);
	destroy_job(job);
	return false;
}

static bool crc_map_txt (tjob * job, struct scatterlist * sg, uint len) {

    sg_set_buf(sg, dma_alloc_coherent(NULL,
									  len,
									  &sg_dma_address(sg),
									  GFP_ATOMIC), len);
	
	if (dma_mapping_error(NULL, sg_dma_address(sg))) {
		
		pr_err("%u >> Dma allocation failed (%p, 0x%08x).\n", job->id, sg_virt(sg), sg_dma_address(sg));
		return false;
		
	} else
		pr_warn("%u >> Dma allocation success (%p, 0x%08x).\n", job->id, sg_virt(sg), sg_dma_address(sg));
	//sg_mark_end(sg);
	
	return true;
	
}

static struct scatterlist * crc_updt_txt (tjob * job, struct scatterlist * src, text * txt)
{

	ahash_d * spec_data = job->data->spec;
	uint len = ALIGN(txt->len, crypto_ahash_alignmask(spec_data->tfm) + 1);
	
	if (crc_map_txt(job, src, len)) {
		
		if (len != txt->len)
			memset(sg_virt(src),0, len); /* Zero the buffer first. */

		memcpy(sg_virt(src), txt->text, txt->len); /* Fill with info, alignment padded with zeroes */
		
	} else 	
		return NULL;
	

	spec_data->updt_cnt ++;
	pr_info("%u >> CRC: Adding text %u, total: %u.\n", job->id, txt->id, spec_data->updt_cnt);
	
	return src;
	
}

static crc_updt * init_crc_updt(uint num) {

	crc_updt * updt = kzalloc(sizeof(crc_updt), GFP_KERNEL);

	if (!updt)
		return NULL;

	if (sg_alloc_table(&updt->src, num, GFP_KERNEL))
		goto fail;
	
	return updt;
	
 fail:
	
	sg_free_table(&updt->src);
	kfree(updt);

	return NULL;
}

static bool crc_set_req (tjob * job, struct scatterlist * src) {

	ahash_d * spec_data = job->data->spec;

	spec_data->req->result = kzalloc(crypto_ahash_digestsize(spec_data->tfm) * 13, GFP_KERNEL); //spec_data->req->result ? : 

	if (!spec_data->req->result) {

		pr_err("%u >> No result, aborting.\n", job->id);
		return false;
		
	}
	
	ahash_request_set_crypt (spec_data->req, src, spec_data->req->result, job->data->nbytes);
	return true;
}

static struct scatterlist * crc_add_args ( tjob * job ) {

	text * txt;
	ahash_d * spec_data = job->data->spec;
	struct scatterlist * ret, * aux;
	uint j = 0;

	crc_updt * updt = init_crc_updt(job->args < 0 ? job->data->text_num : 1);
	
	if (!updt)
		return NULL;

	ret = aux = updt->src.sgl;
	
	if (job->args < 0) {
		
		text_for_each(txt) {
			
			if (!crc_updt_txt (job, aux, txt))
				goto err_map;

			if (!j)
				ret = aux;
			
			j++;
			aux = sg_next(aux);
		}

		//sg_mark_end(aux);
		
	} else {
		
		txt = get_text_by_id(job->args);
		
		if (!txt) {
			
			pr_err("%u >> Bad tid provided, aborting.\n", job->id);
			return NULL;
					
		}
		
	    ret = crc_updt_txt (job, updt->src.sgl, txt);

		if (!ret)
			goto err_single;

		//sg_mark_end(spec_data->req->src);
	}

	list_add_tail(&updt->elem, &spec_data->updates);
	crc_set_req(job, ret);
	
	return spec_data->req->src;

 err_map:
	
	ret = updt->src.sgl;
	
	while (ret) {
		
		dma_free_coherent(NULL, sg_dma_len(ret), sg_virt(ret), sg_dma_address(ret));
		ret = sg_next(ret);
	}
	
 err_single:
	
	sg_free_table(&updt->src);
	kfree(updt);
	
	return NULL;
}

bool do_crc_digest ( tjob * job ) {

	ahash_d * spec_data;
	
	if (is_initialized(job)) {
		
		spec_data = job->data->spec;
		
		if (job->args == 0) {

			job->stime = jiffies;
			if (crypto_ahash_final(spec_data->req)) {

				pr_err("%u >> Error finalising request, aborting.\n", job->id);
				return false;
				
			}

		} else {

			if (!crc_add_args (job))
				return false;

			job->stime = jiffies;
			if (crypto_ahash_finup(spec_data->req)) {

				pr_err("%u >> Error finalising request, aborting.\n", job->id);
			    return false;
								
			}
			
		}

	} else {

		if (!init_crc(job, false))
			return false;
		
		spec_data = job->data->spec;
		
		if (!crc_add_args (job))
			return false;

		job->stime = jiffies;
		if (crypto_ahash_digest(spec_data->req))
			return false;
	}
	
	return true;
}

bool do_crc_update ( tjob * job ) {

	ahash_d * spec_data;
	bool init = true;
	
	if (!is_initialized(job)) 
		init = init_crc (job, true);
	
	if (init) {
		
		spec_data = job->data->spec;
		
	    if (!crc_add_args (job))
			return false;
		
		if(crypto_ahash_update(spec_data->req))
			return false;

	} else
		return false;
	
	return true;
	
}

bool do_crc_import ( tjob * job ) {

	return false;

}

bool do_crc_export ( tjob * job ) {

	return false;

}
