#include "dmatest.h"

bool do_slave_dev_to_mem ( telem * tinfo ) {
    
	unsigned long flags = 0;
	tdata * block, * temp;
    struct sg_table sgt;
	struct scatterlist * sgl;
	int ret;
	
	tinfo->amount = mode_2d ? DIV_ROUND_UP_ULL(glob_size, PAGE_SIZE) : 1;
	tinfo->isize = mode_2d ? PAGE_SIZE : glob_size;
	tinfo->osize = sizeof(unsigned long long);
	
	pr_info("Entering %s, size: %s, amount: %u\n", __func__, hr_size, tinfo->amount);
	
	if ( !allocate_arrays (tinfo, 1, tinfo->isize, tinfo->osize) )
	    goto cfg_error;
	else {

		if ( !allocate_arrays (tinfo, (tinfo->amount - 1), tinfo->isize, 0) )
			goto cfg_error;	
		else
			pr_info("Succefully mapped dst and src dma addresses.\n");
	}

    temp = list_first_entry(&tinfo->data, tdata, elem);
	
	tinfo->config.direction = DMA_DEV_TO_MEM;
    tinfo->config.src_addr_width = DMA_SLAVE_BUSWIDTH_8_BYTES;
    tinfo->config.src_addr = temp->src_dma;
	
	*temp->output = dvc_value;
	
	ret = dmaengine_slave_config(tinfo->chan, &tinfo->config);
	
	/* All functions that run "device_control" must return the status of the channel, in this case DMA_SUCCESS */
	if (ret != DMA_SUCCESS)
		pr_warn("Strange status: %d\n", ret);
	else 
		pr_info("Slave config OK. (%d)\n", ret);
	
	if (tinfo->amount != 1) {
		
	    sg_alloc_table(&sgt, tinfo->amount, GFP_KERNEL);
		sgl = sgt.sgl;
		block = temp;
		
		while (sgl) {
			
			sg_dma_address(sgl) = block->dst_dma;
			sg_dma_len(sgl) = tinfo->isize;
			
		    sgl = sg_next(sgl);
			block = list_next_entry(block, elem);
		}
		
	    tinfo->tx_desc = dmaengine_prep_slave_sg(tinfo->chan,
												 sgt.sgl,
												 tinfo->amount,
												 DMA_DEV_TO_MEM,
												 flags);
		
		sg_free_table(&sgt);
			
	} else 
		tinfo->tx_desc = dmaengine_prep_slave_single(tinfo->chan,
													 temp->dst_dma,
													 tinfo->isize,
													 DMA_DEV_TO_MEM,
													 flags);
	
	if (!submit_transaction(tinfo))
		goto cfg_error;
	
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

bool do_slave_dev_to_dev ( telem * tinfo ) { 
	
	return false;
}

bool do_dma_slave_sg ( telem * tinfo ) {
	
	return
		do_slave_dev_to_mem ( tinfo ) &&
		do_slave_mem_to_dev ( tinfo ) &&
		do_slave_dev_to_dev ( tinfo );
}
