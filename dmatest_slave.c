#include "dmatest.h"

bool do_slave_dev_to_mem ( telem * tinfo ) {
    
	unsigned long flags = 0;
	tdata * block, * temp;
	int ret, i;
	
	tinfo->amount = DIV_ROUND_UP_ULL(glob_size, PAGE_SIZE);
	tinfo->isize = PAGE_SIZE;
	tinfo->osize = 1;

	pr_info("Entering %s, size: %s, amount: %u\n", __func__, hr_size, tinfo->amount);
	
	if ( !allocate_arrays (tinfo, tinfo->amount, tinfo->isize, tinfo->osize) )
	    goto cfg_error;
	else
		pr_info("Succefully mapped dst and src dma addresses.\n");
	
	list_for_each_entry (block, &tinfo->data, elem) {
		
		for (i = 0; i < tinfo->osize; i++)
			block->output[i] = dvc_value; 
		
		block->config.direction = DMA_DEV_TO_MEM;
		block->config.src_addr_width = DMA_SLAVE_BUSWIDTH_8_BYTES;
		block->config.src_addr = block->src_dma;
		
		ret = dmaengine_slave_config(tinfo->chan, &block->config);
		
		/* All functions that run "device_control" must return the status of the channel, in this case DMA_SUCCESS */
		if (ret != DMA_SUCCESS)
			pr_warn("Strange status: %d\n", ret);
		else 
			pr_info("Slave config OK. (%d)\n", ret);
		
		block->tx_desc = dmaengine_prep_slave_single(tinfo->chan,
													 block->dst_dma,
													 tinfo->isize,
													 DMA_DEV_TO_MEM,
													 flags);
		if(!block->tx_desc) {
			
			pr_err("Unable to get descriptor\n");
			goto cfg_error;
			
		} else
			pr_info("Got descriptor: %pB\n", block->tx_desc);
		
		block->tx_desc->callback = async_mode ? (void *) &finish_transaction : NULL;
		block->tx_desc->callback_param = async_mode ? (void *) tinfo : NULL;
		
		block->tx_cookie = dmaengine_submit(block->tx_desc);
		
		if(block->tx_cookie < 0) 
			pr_err("Error submitting transaction: %d\n", block->tx_cookie);
		else
			pr_info("Cookie submitted: %d\n", block->tx_cookie);
	}
	
	tinfo->stime = jiffies;
	dma_async_issue_pending(tinfo->chan);
	
	if (!async_mode) 	
		finish_transaction ( tinfo );
	
	return true;
	
 cfg_error:
	
	pr_err("Configuration error.");
	
    list_for_each_entry_safe(block, temp, &tinfo->data, elem) {
		
	    dma_free_coherent(tinfo->chan->device->dev, tinfo->isize, block->input, block->dst_dma);
	    dma_free_coherent(tinfo->chan->device->dev, tinfo->osize, block->output, block->src_dma);
		list_del(&block->elem);
		kfree(block);
	}
	
	return false;
}

bool do_slave_mem_to_dev ( telem * tinfo ) {
	
	return false;
}

bool do_slave_dev_to_dev ( telem * tinfo ) { /* A lo loco con el mocazo! ...*/
	
	return false;
}

bool do_dma_slave_sg ( telem * tinfo ) {
	
	return
		do_slave_dev_to_mem ( tinfo ) &&
		do_slave_mem_to_dev ( tinfo ) &&
		do_slave_dev_to_dev ( tinfo );
}
