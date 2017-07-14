#include "dmatest.h"

bool do_dma_scatter_gather ( telem * node )
{
	unsigned long flags = 0;
	tdata * block, * temp;
    //struct sg_table src_sgt;
	struct scatterlist src_sgl;
	//struct sg_table dst_sgt;
	struct scatterlist dst_sgl;
	struct scatterlist * src_aux, * dst_aux;
	uint src_amount, dst_amount;
	int j, i;
	tjob * tinfo = init_job(node, DMA_SG, 0);

	get_random_bytes(&src_amount, 32);
	src_amount %= periods;
	src_amount = ALIGN(src_amount, sizeof(unsigned long long));
	
	get_random_bytes(&dst_amount, 32);
	dst_amount %= periods;
	dst_amount = ALIGN(dst_amount, sizeof(unsigned long long));
	
	tinfo->real_size = ALIGN(glob_size, sizeof(unsigned long long));
	tinfo->amount = max(src_amount, dst_amount);
	
	tinfo->isize = DIV_ROUND_UP_ULL(tinfo->real_size, dst_amount);
	tinfo->osize = DIV_ROUND_UP_ULL(tinfo->real_size, src_amount);
	
	tinfo->tname = __func__;
	
	pr_info("%u >> Entering %s, size: %s, src_amount: %u, dst_amount: %u\n", tinfo->parent->id, tinfo->tname, hr_size, src_amount, dst_amount);


	
	if ( !allocate_arrays (tinfo, src_amount, 0, tinfo->osize) )
	    return false;
	else {
		
		if ( !allocate_arrays (tinfo, dst_amount, tinfo->isize, 0) )
			goto cfg_error;	
		else
			pr_info("%u >> Succefully mapped dst and src dma addresses.\n", tinfo->parent->id);
	}
	
	sg_init_table(&src_sgl, src_amount);
	sg_init_table(&dst_sgl, dst_amount);
	temp = block = list_first_entry(&tinfo->data, tdata, elem);

	while (!temp->dst_dma)
		temp = list_next_entry(block, elem);
	
	j = 0;
	src_aux = &src_sgl;
	dst_aux = &dst_sgl;
	
	while (src_aux || dst_aux) {

		if (src_aux) {
			for (i = 0; i < (tinfo->osize / sizeof(unsigned long long)); i++)
				block->output[i] = dvc_value + i + j;
		}
		
		if (src_aux) {
			sg_dma_address(src_aux) = block->src_dma;
			sg_set_buf(src_aux, block->output, tinfo->osize);
		}

		if (dst_aux) {
			sg_dma_address(dst_aux) = temp->dst_dma;
			sg_set_buf(dst_aux, temp->input, tinfo->isize);
		}
		
		if (verbose >= 2)
			pr_info("%u >> Block %d (0x%08x -> 0x%08x): size_src->%u, size_dst->%u\n", tinfo->parent->id, j, block->src_dma, block->dst_dma, sg_dma_len(src_aux), sg_dma_len(dst_aux));
		
		src_aux = sg_next(src_aux);
		dst_aux = sg_next(dst_aux);
		block = list_next_entry(block, elem);
		temp = list_next_entry(temp, elem);  
		j++;
	}

	tinfo->tx_desc = dmaengine_prep_dma_sg(tinfo->parent->chan,
										   &src_sgl, src_amount,
										   &dst_sgl, dst_amount,
										   flags);
	
	if (!tinfo->tx_desc)
		goto cfg_error;
	
	if (!submit_transaction(tinfo))
		goto cfg_error;
	
	return true;
	
 cfg_error:
	
	pr_err("%u >> Configuration error.", tinfo->parent->id);
	
    list_for_each_entry_safe(block, temp, &tinfo->data, elem) {
		
		if (block->dst_dma)
			dma_free_coherent(tinfo->parent->chan->device->dev, tinfo->isize, block->input, block->dst_dma);
		
		if (block->src_dma)
			dma_free_coherent(tinfo->parent->chan->device->dev, tinfo->osize, block->output, block->src_dma);
		
		list_del(&block->elem);
		kfree(block);
	}
	
	return false;
};


/* 
   Maybe it would be nice to split this one to have dedicated tests 
   for asimetric transactions with sgents of diferents sizes for src and dst 
   such as:

   src: |====================| |==========================|
   dst: |=========| |=====| |========| |==================|
   
   src: |=========| |=====| |========| |==================|
   dst: |====================| |==========================| 

   [ . . . ]
   
   Or those achivable with interleaved:

   src: |===================================================|
   dst: |======| |======| |======| |======| |======| |======|
   
   or viceversa.

   etc, etc.

   Whatever the final implementation became we need to have in mind that there are 
   several scenarios here.
   
*/
