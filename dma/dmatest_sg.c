#include "dmatest.h"

static bool is_last_src (tjob * tinfo, tdata * block) {

	if (list_is_last(&block->elem, &tinfo->data)) 
		return true;
	else
		return !list_next_entry(block, elem)->src_dma;

}

static bool is_last_dst (tjob * tinfo, tdata * block) {

	if (list_is_last(&block->elem, &tinfo->data)) 
		return true;
	else
		return !list_next_entry(block, elem)->dst_dma;

}

bool do_dma_scatter_gather ( telem * node, bool same_shape )
{
	unsigned long flags = 0;
	tdata * block, * temp;
    struct sg_table src_sgt;
	struct sg_table dst_sgt;
	struct scatterlist * src_aux, * dst_aux;
	uint src_amount = 0, dst_amount = 0, multi = 1, min_amount, max_amount;
    int last_src = 0, last_dst = 0;
	int j, i;
	tjob * tinfo = init_job(node, DMA_SCAT_GATH, 0);

	tinfo->real_size = ALIGN(glob_size, sizeof(unsigned long long));   
	
	while (multi <= 1) {
		
		get_random_bytes_arch(&multi, 4);
	    multi %= periods;
		
	}
	
	if (same_shape) {

		while (!tinfo->amount) {
			
			get_random_bytes_arch(&tinfo->amount, 4);
			tinfo->amount %= periods;
		}
		
		dst_amount = src_amount = tinfo->amount;
		
		tinfo->osize = tinfo->isize = ALIGN(DIV_ROUND_UP_ULL(tinfo->real_size, tinfo->amount), sizeof(unsigned long long));

		tinfo->real_size = tinfo->osize * tinfo->amount;
			
	} else if (direction) {
		
		while (!src_amount || (src_amount % 2)) {
			get_random_bytes_arch(&src_amount, 4);
			src_amount %= periods;
		}
		
	    tinfo->osize = ALIGN(DIV_ROUND_UP_ULL(tinfo->real_size, src_amount), sizeof(unsigned long long));
		tinfo->real_size = tinfo->osize * src_amount;
		
		while (tinfo->osize * src_amount != tinfo->isize * dst_amount) {

			get_random_bytes_arch(&multi, 4);
			multi %= periods;

			if (multi > 1) {
				
				tinfo->isize = tinfo->osize * multi;
			    dst_amount = ((tinfo->osize * src_amount) / tinfo->isize);
				
			}
		}

		tinfo->amount = dst_amount;
		
	} else {

		while (!dst_amount || (dst_amount % 2)) {
			get_random_bytes_arch(&dst_amount, 4);
			dst_amount %= periods;
		}
		
		tinfo->isize = ALIGN(DIV_ROUND_UP_ULL(tinfo->real_size, dst_amount), sizeof(unsigned long long));
		tinfo->real_size = tinfo->isize * dst_amount;
		
		while (tinfo->osize * src_amount != tinfo->isize * dst_amount) {

			get_random_bytes_arch(&multi, 4);
			multi %= periods;
		
			if (multi > 1) {
				
				tinfo->osize = tinfo->isize * multi;
				src_amount = ((tinfo->isize * dst_amount) / tinfo->osize);
			}
		}
		
		tinfo->amount = src_amount;
	}
	
	tinfo->tname = __func__;
	
	min_amount = min(src_amount, dst_amount);
	max_amount = max(src_amount, dst_amount);
	
	pr_info("%u >> Entering %s, size: %s, src_amount: %u * %u, dst_amount: %u * %u\n", tinfo->parent->id, tinfo->tname, hr_size, src_amount, tinfo->osize, dst_amount, tinfo->isize);
	
	if ( !allocate_arrays (tinfo, min_amount, tinfo->isize, tinfo->osize) )
	    return false;
	else if (min_amount != max_amount) {
		
		if ( !allocate_arrays (tinfo, max_amount - min_amount, max_amount == dst_amount ? tinfo->isize : 0, max_amount == src_amount ? tinfo->osize : 0) )
			goto cfg_error;	
		else
			pr_info("%u >> Succefully mapped dst and src dma addresses.\n", tinfo->parent->id);
	} else
		pr_info("%u >> Succefully mapped dst and src dma addresses.\n", tinfo->parent->id);
	
	if (sg_alloc_table(&src_sgt, src_amount, GFP_KERNEL))
		goto cfg_error;
	
	if (sg_alloc_table(&dst_sgt, dst_amount, GFP_KERNEL))
		goto cfg_error;
	
    block = list_first_entry(&tinfo->data, tdata, elem);

	j = 0;
	src_aux = src_sgt.sgl;
	dst_aux = dst_sgt.sgl;

	while (block) {
				
		if (src_aux) {
			
			for (i = 0; i < (tinfo->osize / sizeof(unsigned long long)); i++)
				block->output[i] = dvc_value + i + j;
			
			sg_dma_address(src_aux) = block->src_dma;
			sg_set_buf(src_aux, block->output, tinfo->osize);

			last_src = !is_last_src(tinfo, block) ? list_next_entry(block, elem)->src_dma - (sg_dma_address(src_aux) + sg_dma_len(src_aux)) : -1;
			src_aux = sg_next(src_aux);

		} else
			last_src = -1;

		if (dst_aux) {
	
			sg_dma_address(dst_aux) = block->dst_dma;
			sg_set_buf(dst_aux, block->input, tinfo->isize);

			last_dst = !is_last_dst(tinfo, block) ? list_next_entry(block, elem)->dst_dma - (sg_dma_address(dst_aux) + sg_dma_len(dst_aux)) : -1;
			dst_aux = sg_next(dst_aux);
			
		} else
			last_dst = -1;
 
		if (verbose >= 2)
			pr_info("%u >> Block %3d (0x%08x -> 0x%08x), icg_src = %8d, icg_dst = %8d\n", tinfo->parent->id, j, block->src_dma, block->dst_dma, last_src, last_dst);

		
		block = !list_is_last(&block->elem, &tinfo->data) ? list_next_entry(block, elem) : NULL;
		
		j++;
	}

	tinfo->tx_desc = dmaengine_prep_dma_sg(tinfo->parent->chan,
										   dst_sgt.sgl, dst_amount,
										   src_sgt.sgl, src_amount,
										   flags);	
	sg_free_table(&src_sgt);
	sg_free_table(&dst_sgt);


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
