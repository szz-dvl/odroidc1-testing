#include "cryptotest.h"

#define CRC_ALGNAME         "crc-32-hw"

static bool is_initialized (tjob * job) {

	return job->data->spec;
	
}

static bool init_crc (tjob * job, bool init_drv) {

	ahash_d * spec_data;
	
	spec_data = job->data->spec = (skcip_d *) kzalloc(sizeof(skcip_d), GFP_KERNEL);
	if (!spec_data)
	    goto fail;
	
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
	if (!spec_data->req)
		goto fail;

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

bool do_crc_digest ( tjob * job ) {

	ahash_d * spec_data = job->data->spec;

	if (is_initialized(job)) {

		if (job->args < 0) { /* !!! */

			if (spec_data->updt_cnt) {
				
				if (crypto_ahash_final(spec_data->req)) {

					pr_err("%u >> Error finalising request, aborting.\n", job->id);
					return false;
								
				}

			} else
				goto add_txt;

		} else {

		add_txt:
			
			/* Map the text in job->args*/
			
			if (crypto_ahash_finup(spec_data->req)) {

				pr_err("%u >> Error finalising request, aborting.\n", job->id);
			    return false;
								
			}
			
		}

	} else {

		if (!init_crc(job, false))
			return false;
	}


	if (!spec_data->updt_cnt) {

		/* Map the text in job->args*/

		cpu_relax();
	}
		
	
	if (crypto_ahash_digest(spec_data->req))
		return false;
		
	
	return true;
}

bool do_crc_update ( tjob * job ) {

	ahash_d * spec_data;
	bool init = true;
	
	if (!is_initialized(job)) 
		init = init_crc (job, true);
	
	if (init) {
		
		spec_data = job->data->spec;
		
		/* Map the text in job->args*/

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
