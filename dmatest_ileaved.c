#include "dmatest.h"

#define ILEAVED_TEST 3

/* 
   Fake:
   
   As the minimum allocation size we can get here, either from the atomic pool or from CMA zone, is PAGE_SIZE
   due to alignment requeriments we will merge "tinfo->amount" arrays of size PAGE_SIZE into one big array, if 
   2D mode evaluates to true we will make the arrays a little bit bigger to test ICG.
   
*/

bool do_interleaved_mem_to_mem ( telem * node ) {
	
    struct dma_interleaved_template *xt;
	unsigned long flags = 0;
	tdata * block, * temp;
    uint last_icg = 0;
	int i, j = 0;
	unsigned long array_size;
	tjob * tinfo = init_job(node, ILEAVED_TEST, 0);
	
	array_size = mode_2d ? (PAGE_SIZE + (sizeof(unsigned long long) * 4)) : PAGE_SIZE;
	tinfo->amount = DIV_ROUND_UP_ULL(glob_size, array_size);

	tinfo->tname = __func__;

	if (mode_2d)
		tinfo->real_size = tinfo->amount * array_size;
	
	pr_info("Entering %s, size: %s, amount: %u\n", tinfo->tname, hr_size, tinfo->amount);
	
	xt = kzalloc(sizeof(struct dma_interleaved_template) +
				 tinfo->amount * sizeof(struct data_chunk), GFP_KERNEL);
	
	if (!xt) 
		return false;
	
	tinfo->isize = merge ? array_size * tinfo->amount : array_size;
	tinfo->osize = merge ? array_size : array_size * tinfo->amount;
	
	if ( !allocate_arrays (tinfo, 1, tinfo->isize, tinfo->osize) )
		goto cfg_error;
	else {
		
		if ( !allocate_arrays (tinfo, (tinfo->amount - 1), merge ? 0 : tinfo->isize, merge ? tinfo->osize : 0) ) 
			goto cfg_error;
		else
			pr_info("Succefully mapped dst and src dma addresses.\n");
	}

	temp = list_first_entry(&tinfo->data, tdata, elem);
	
	xt->src_start = temp->src_dma;
	xt->dst_start = temp->dst_dma;
	xt->dir = DMA_MEM_TO_MEM;
	xt->src_inc = true;
	xt->dst_inc = true;
	xt->src_sgl = merge ? true : false;
	xt->dst_sgl = merge ? false : true;
	xt->numf = 1; 
	xt->frame_size = tinfo->amount;

	if (!merge) {

		for (i = 0; i < (tinfo->osize / sizeof(unsigned long long)); i++)
			temp->output[i] = dvc_value + i;
		
	}
	
	list_for_each_entry (block, &tinfo->data, elem) {
		
		if (merge) {

			for (i = 0; i < (tinfo->osize / sizeof(unsigned long long)); i++)
				block->output[i] = dvc_value + i + j; 
		}
		
		xt->sgl[j].size = merge ? tinfo->osize : tinfo->isize ;
		xt->sgl[j].icg = !list_is_last(&block->elem, &tinfo->data) ?
			merge ? list_next_entry(block, elem)->src_dma - (block->src_dma + xt->sgl[j].size) :
			list_next_entry(block, elem)->dst_dma - (block->dst_dma + xt->sgl[j].size) :
		    last_icg;

		if (verbose >= 2)
			pr_info("Block %d (0x%08x -> 0x%08x): size->%u, icg->%u\n", j, block->src_dma, block->dst_dma, xt->sgl[j].size, xt->sgl[j].icg);
		
		last_icg = xt->sgl[j].icg;
		j++;
	}
	
	pr_info("Config ready!\n");
    tinfo->tx_desc = dmaengine_prep_interleaved_dma(tinfo->parent->chan, xt, flags);

	if (!submit_transaction(tinfo))
		goto cfg_error;
	
	kfree(xt);
	
	return true;
	
 cfg_error:
	pr_err("Configuration error.");
	
	list_for_each_entry_safe(block, temp, &tinfo->data, elem) {
		
		if (block->dst_dma)
			dma_free_coherent(tinfo->parent->chan->device->dev, tinfo->isize, block->input, block->dst_dma);
		
	    dma_free_coherent(tinfo->parent->chan->device->dev, tinfo->osize, block->output, block->src_dma);
		
		list_del(&block->elem);
		kfree(block);
	}
	
	kfree(xt);
	
	return false;
}

bool do_interleaved_dev_to_mem ( telem * node )
{
    struct dma_interleaved_template *xt;
	unsigned long flags = 0;
	tdata * block, * temp;
    uint last_icg = 0;
	int j = 0;
	unsigned long array_size;
	tjob * tinfo = init_job(node, ILEAVED_TEST, 1);
	
	array_size = mode_2d ? (PAGE_SIZE + (sizeof(unsigned long long) * 4)) : PAGE_SIZE;
	tinfo->amount = mode_2d ? DIV_ROUND_UP_ULL(glob_size, array_size) : 1;
	
	tinfo->tname = __func__;

	if (mode_2d)
		tinfo->real_size = tinfo->amount * array_size;
	
	pr_info("Entering %s, size: %s, amount: %u\n", tinfo->tname, hr_size, tinfo->amount);
	
	xt = kzalloc(sizeof(struct dma_interleaved_template) +
				 tinfo->amount * sizeof(struct data_chunk), GFP_KERNEL);
	
	if (!xt) 
		return false;
	
	tinfo->isize = mode_2d ? array_size : glob_size;
	tinfo->osize = sizeof(unsigned long long);
	
	if ( !allocate_arrays (tinfo, 1, tinfo->isize, tinfo->osize) )
		goto cfg_error;
	else {
		
		if ( !allocate_arrays (tinfo, (tinfo->amount - 1), tinfo->isize, 0) ) 
			goto cfg_error;
		else
			pr_info("Succefully mapped dst and src dma addresses.\n");
	}
	
	temp = list_first_entry(&tinfo->data, tdata, elem);
	
	xt->src_start = temp->src_dma;
	xt->dst_start = temp->dst_dma;
	xt->dir = DMA_DEV_TO_MEM;
	xt->src_inc = false;
	xt->dst_inc = true;
	xt->src_sgl = false;
	xt->dst_sgl = mode_2d ? true : false;
	xt->numf = 1; 
	xt->frame_size = tinfo->amount;

	*temp->output = dvc_value;
		
	list_for_each_entry (block, &tinfo->data, elem) {
		
		xt->sgl[j].size = tinfo->isize;
		xt->sgl[j].icg = !list_is_last(&block->elem, &tinfo->data) ?
			list_next_entry(block, elem)->dst_dma - (block->dst_dma + xt->sgl[j].size) :
		    last_icg;

		if (verbose >= 2)
			pr_info("Block %d (0x%08x -> 0x%08x): size->%u, icg->%u\n", j, block->src_dma, block->dst_dma, xt->sgl[j].size, xt->sgl[j].icg);
		
		last_icg = xt->sgl[j].icg;
		j++;
	}
	
	pr_info("Config ready!\n");
    tinfo->tx_desc = dmaengine_prep_interleaved_dma(tinfo->parent->chan, xt, flags);

	if (!submit_transaction(tinfo))
		goto cfg_error;
	
	kfree(xt);
	
	return true;
	
 cfg_error:
	
	pr_err("Configuration error.");
	
	list_for_each_entry_safe(block, temp, &tinfo->data, elem) {
		
		dma_free_coherent(tinfo->parent->chan->device->dev, tinfo->isize, block->input, block->dst_dma);
		
		if (block->src_dma)
			dma_free_coherent(tinfo->parent->chan->device->dev, tinfo->osize, block->output, block->src_dma);
		
		list_del(&block->elem);
		kfree(block);
	}
	
	kfree(xt);
	
	return false;
};

bool do_interleaved_mem_to_dev ( telem * node )
{
	return false;
};

bool do_interleaved_dev_to_dev ( telem * node )
{
	return false;
};

bool do_dma_ileaved ( telem * node )
{
	return
		do_interleaved_mem_to_mem ( node ) &&
		do_interleaved_dev_to_mem ( node ) &&
		do_interleaved_mem_to_dev ( node ) &&
		do_interleaved_dev_to_dev ( node );
}
