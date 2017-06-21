#include "dmatest.h"

bool do_interleaved_mem_to_mem ( telem * tinfo ) {
	
    struct dma_interleaved_template *xt;
	unsigned long flags = 0;
	tdata * block, * temp;
    uint last_icg = 0;
	int i, j = 0;
	unsigned long array_size;
	
	array_size = mode_2d ? (PAGE_SIZE - (sizeof(unsigned long long) * 4)) : PAGE_SIZE;
	tinfo->amount = DIV_ROUND_UP_ULL(glob_size, array_size);
	
	pr_info("Entering %s, size: %s, amount: %u\n", __func__, hr_size, tinfo->amount);
	
	/* 
	   
	   As the minimum allocation size we can get here, either from the atomic pool or from CMA zone, is PAGE_SIZE
	   due to alignment requeriments we will merge "tinfo->amount" arrays of size PAGE_SIZE into one big array, if 
	   2D mode evaluates to true we will make the arrays a little bit smaller to test ICG.
	   
	*/
	
	xt = kzalloc(sizeof(struct dma_interleaved_template) +
				 tinfo->amount * sizeof(struct data_chunk), GFP_KERNEL);
	
	if (!xt) 
		return false;
	
	tinfo->isize = array_size * tinfo->amount;
	tinfo->osize = array_size;
	
	if ( !allocate_arrays (tinfo, 1, tinfo->isize, tinfo->osize) )
		goto cfg_error;
	else {
		
		if ( !allocate_arrays (tinfo, (tinfo->amount - 1), 0, tinfo->osize) ) 
			goto cfg_error;
		else
			pr_info("Succefully mapped dst and src dma addresses.\n");
	}
	
    temp = list_first_entry_or_null(&tinfo->data, tdata, elem);
	
	xt->src_start = temp->src_dma;
	xt->dst_start = temp->dst_dma;
	xt->dir = DMA_MEM_TO_MEM;
	xt->src_inc = true;
	xt->dst_inc = true;
	xt->src_sgl = true;
	xt->dst_sgl = false;
	xt->numf = 1; 
	xt->frame_size = tinfo->amount;
	
	list_for_each_entry (block, &tinfo->data, elem) {
		
		for (i = 0; i < (tinfo->osize / sizeof(unsigned long long)); i++)
			block->output[i] = dvc_value + i + j; 
		
		xt->sgl[j].size = tinfo->osize;
		xt->sgl[j].icg = !list_is_last(&block->elem, &tinfo->data) ?
			list_next_entry(block, elem)->src_dma - (block->src_dma + xt->sgl[j].size) :
		    15;//last_icg;
		
		pr_info("Block %d (0x%08x): size->%u, icg->%u\n", j, block->src_dma, xt->sgl[j].size, xt->sgl[j].icg);
		
		last_icg = xt->sgl[j].icg;
		j++;
	}
	
	pr_info("Config ready!\n");
    temp->tx_desc = dmaengine_prep_interleaved_dma(tinfo->chan, xt, flags);
	
	if(!temp->tx_desc) {
		pr_err("Unable to get descriptor\n");
		goto cfg_error;
	} else
		pr_info("Got descriptor: %pB\n", temp->tx_desc);
	
    temp->tx_desc->callback = async_mode ? (void *) &finish_transaction : NULL;
    temp->tx_desc->callback_param = async_mode ? (void *) tinfo : NULL;
	
	temp->tx_cookie = dmaengine_submit(temp->tx_desc);
	
	if (temp->tx_cookie < 0) {
		pr_err("Error submitting transaction: %d\n", temp->tx_cookie);
	 	goto cfg_error;
	} else
		pr_info("Cookie submitted: %d\n", temp->tx_cookie);
	
	tinfo->stime = jiffies;
	dma_async_issue_pending(tinfo->chan);
	
	if (!async_mode) 
		finish_transaction ( tinfo );
	
	kfree(xt);
	
	return true;
	
 cfg_error:
	pr_err("Configuration error.");
	
	list_for_each_entry_safe(block, temp, &tinfo->data, elem) {
		
		if (block->dst_dma)
			dma_free_coherent(tinfo->chan->device->dev, tinfo->isize, block->input, block->dst_dma);
		
	    dma_free_coherent(tinfo->chan->device->dev, tinfo->osize, block->output, block->src_dma);
		list_del(&block->elem);
		kfree(block);
	}
	
	kfree(xt);
	
	return false;
}

bool do_interleaved_dev_to_mem ( telem * tinfo )
{
	return false;
};

bool do_interleaved_mem_to_dev ( telem * tinfo )
{
	return false;
};

bool do_interleaved_dev_to_dev ( telem * tinfo )
{
	return false;
};

bool do_dma_ileaved ( telem * tinfo )
{
	return
		do_interleaved_mem_to_mem ( tinfo ) &&
		do_interleaved_dev_to_mem ( tinfo ) &&
		do_interleaved_mem_to_dev ( tinfo ) &&
		do_interleaved_dev_to_dev ( tinfo );
}
