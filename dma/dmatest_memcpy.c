#include "dmatest.h"

bool do_dma_memcpy ( telem * node )
{
	unsigned long flags = 0;
	tdata * block;
	uint i;
	tjob * tinfo = init_job(node, DMA_MCPY, 0);

	tinfo->amount = 1;
	tinfo->real_size = ALIGN(glob_size, sizeof(unsigned long long));
	tinfo->osize = tinfo->isize = tinfo->real_size;

	tinfo->tname = __func__;
	
	pr_info("%u >> Entering %s, size: %s\n", tinfo->parent->id, tinfo->tname, hr_size);

	if ( !allocate_arrays (tinfo, tinfo->amount, tinfo->isize, tinfo->osize) )
	    return false;
	else
		pr_info("%u >> Succefully mapped dst and src dma addresses.\n", tinfo->parent->id);

	block = list_first_entry(&tinfo->data, tdata, elem);

	for (i = 0; i < tinfo->osize /sizeof(unsigned long long); i++)
			block->output[i] = dvc_value + i;
	
	tinfo->tx_desc = dmaengine_prep_dma_memcpy (tinfo->parent->chan, block->dst_dma, block->src_dma, tinfo->real_size, flags);

	if (!tinfo->tx_desc)
		goto cfg_error;
	
	if (!submit_transaction(tinfo))
		goto cfg_error;
	
	return true;
	
 cfg_error:
	
	pr_err("%u >> Configuration error.", tinfo->parent->id);
	
	dma_free_coherent(tinfo->parent->chan->device->dev, tinfo->osize, block->output, block->src_dma);
	dma_free_coherent(tinfo->parent->chan->device->dev, tinfo->isize, block->input, block->dst_dma);
	
	list_del(&block->elem);
	kfree(block);	
	
	return false;
};

