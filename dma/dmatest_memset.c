#include "dmatest.h"

bool do_dma_memset ( telem * node )
{
	unsigned long flags = 0;
	tdata * block;
	tjob * tinfo = init_job(node, DMA_MSET, 1);

	tinfo->amount = 1;
	tinfo->real_size = ALIGN(glob_size, sizeof(unsigned long long));
	tinfo->isize = tinfo->real_size;

	tinfo->tname = __func__;
	
	pr_info("%u >> Entering %s, size: %s\n", tinfo->parent->id, tinfo->tname, hr_size);

	if ( !allocate_arrays (tinfo, tinfo->amount, tinfo->isize, tinfo->osize) )
	    return false;
	else
		pr_info("%u >> Succefully mapped dst and src dma addresses.\n", tinfo->parent->id);

	block = list_first_entry(&tinfo->data, tdata, elem);
	
	tinfo->memset_val = direction ? dvc_value : -dvc_value;

	tinfo->tx_desc = dmaengine_prep_dma_memset (tinfo->parent->chan, block->dst_dma, tinfo->memset_val, tinfo->isize, flags);

	if (!tinfo->tx_desc)
		goto cfg_error;
	
	if (!submit_transaction(tinfo))
		goto cfg_error;
	
	return true;
	
 cfg_error:
	
	pr_err("%u >> Configuration error.", tinfo->parent->id);
	
	dma_free_coherent(tinfo->parent->chan->device->dev, tinfo->isize, block->input, block->dst_dma);
		
	list_del(&block->elem);
	kfree(block);	
	
	return false;	
};
