#include "dmatest.h"

#define SLAVE_TEST 0

bool do_slave_dev_to_mem ( telem * node ) {
    
	unsigned long flags = 0;
	tdata * block, * temp;
    struct sg_table sgt;
	struct scatterlist * sgl;
	int ret, j;
	tjob * tinfo = init_job(node, SLAVE_TEST, 0); 

	tinfo->amount = mode_2d ? DIV_ROUND_UP_ULL(glob_size, PAGE_SIZE) : 1;
	tinfo->isize = mode_2d ? PAGE_SIZE : glob_size;
	tinfo->osize = sizeof(unsigned long long);
	
	tinfo->tname = __func__; /* to avoid kmalloc, far from well done ... =S */
	
	pr_info("Entering %s, size: %s, amount: %u\n", tinfo->tname, hr_size, tinfo->amount);
	
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
	
	ret = dmaengine_slave_config(tinfo->parent->chan, &tinfo->config);
	
	/* All functions that run "device_control" must return the status of the channel, in this case DMA_SUCCESS */
	if (ret != DMA_SUCCESS)
		pr_warn("Strange status: %d\n", ret);
	else 
		pr_info("Slave config OK. (%d)\n", ret);
	
	if (tinfo->amount != 1) {
		
	    sg_alloc_table(&sgt, tinfo->amount, GFP_KERNEL);
		sgl = sgt.sgl;
		block = temp;
		temp = list_next_entry(block, elem);
		j = 0;
		
		while (sgl) {
			
			sg_dma_address(sgl) = block->dst_dma;
			sg_dma_len(sgl) = tinfo->isize;
			
			if (verbose >= 2)
				pr_info("Block %d (0x%08x -> 0x%08x): size->%u, icg->%u\n", j, block->src_dma, block->dst_dma, sg_dma_len(sgl), (void *) temp != (void *) &tinfo->data ? (temp->dst_dma - (block->dst_dma + sg_dma_len(sgl))) : 0);
			
		    sgl = sg_next(sgl);
			block = temp;
		    temp = list_next_entry(block, elem);  
			j++;
		}

	    tinfo->tx_desc = dmaengine_prep_slave_sg(tinfo->parent->chan,
												 sgt.sgl,
												 tinfo->amount,
												 DMA_DEV_TO_MEM,
												 flags);
		
		sg_free_table(&sgt);
		
	} else 
		tinfo->tx_desc = dmaengine_prep_slave_single(tinfo->parent->chan,
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
		
	    dma_free_coherent(tinfo->parent->chan->device->dev, tinfo->isize, block->input, block->dst_dma);

		if (block->src_dma)
			dma_free_coherent(tinfo->parent->chan->device->dev, tinfo->osize, block->output, block->src_dma);
		
		list_del(&block->elem);
		kfree(block);
	}
	
	return false;
}

bool do_slave_mem_to_dev ( telem * node ) {
	
    unsigned long flags = 0;
	tdata * block, * temp;
    struct sg_table sgt;
	struct scatterlist * sgl;
	int ret, j, i;
	tjob * tinfo = init_job(node, SLAVE_TEST, 1); 
	
	tinfo->amount = mode_2d ? DIV_ROUND_UP_ULL(glob_size, PAGE_SIZE) : 1;
	tinfo->osize = mode_2d ? PAGE_SIZE : glob_size;
	tinfo->isize = sizeof(unsigned long long);
	 
	tinfo->tname = __func__;
	
	pr_info("Entering %s, size: %s, amount: %u\n", tinfo->tname, hr_size, tinfo->amount);
	
	if ( !allocate_arrays (tinfo, 1, tinfo->isize, tinfo->osize) )
	    goto cfg_error;
	else {
		
		if ( !allocate_arrays (tinfo, (tinfo->amount - 1), 0, tinfo->osize) )
			goto cfg_error;	
		else
			pr_info("Succefully mapped dst and src dma addresses.\n");
	}
	
    temp = list_first_entry(&tinfo->data, tdata, elem);
	
	tinfo->config.direction = DMA_MEM_TO_DEV;
    tinfo->config.dst_addr_width = DMA_SLAVE_BUSWIDTH_8_BYTES;
    tinfo->config.dst_addr = temp->dst_dma;
	
	ret = dmaengine_slave_config(tinfo->parent->chan, &tinfo->config);
	
	/* All functions that run "device_control" must return the status of the channel, in this case DMA_SUCCESS */
	if (ret != DMA_SUCCESS)
		pr_warn("Strange status: %d\n", ret);
	else 
		pr_info("Slave config OK. (%d)\n", ret);
	
	if (tinfo->amount != 1) {
		
	    sg_alloc_table(&sgt, tinfo->amount, GFP_KERNEL);
		sgl = sgt.sgl;
		block = temp;
		temp = list_next_entry(block, elem);
		j = 0;
		
		while (sgl) {
			
			for (i = 0; i < (tinfo->osize / sizeof(unsigned long long)); i++)
				block->output[i] = dvc_value + i + j;
			
			sg_dma_address(sgl) = block->src_dma;
			sg_dma_len(sgl) = tinfo->osize;
			
			if (verbose >= 2)
				pr_info("Block %d (0x%08x -> 0x%08x): size->%u, icg->%u\n", j, block->src_dma, block->dst_dma, sg_dma_len(sgl), (void *) temp != (void *) &tinfo->data ? (temp->src_dma - (block->src_dma + sg_dma_len(sgl))) : 0);
			
		    sgl = sg_next(sgl);
			block = temp;
		    temp = list_next_entry(block, elem);  
			j++;
		}

	    tinfo->tx_desc = dmaengine_prep_slave_sg(tinfo->parent->chan,
												 sgt.sgl,
												 tinfo->amount,
												 DMA_MEM_TO_DEV,
												 flags);
		
		sg_free_table(&sgt);
		
	} else {
		
		for (i = 0; i < (tinfo->osize / sizeof(unsigned long long)); i++)
		    temp->output[i] = dvc_value + i;
		
		tinfo->tx_desc = dmaengine_prep_slave_single(tinfo->parent->chan,
													 temp->src_dma,
													 tinfo->osize,
													 DMA_MEM_TO_DEV,
													 flags);
	}
	
	if (!submit_transaction(tinfo))
		goto cfg_error;
	
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
	
	return false;
}

bool do_slave_dev_to_dev ( telem * node ) { 
	
	unsigned long flags = 0;
	tdata * block;
	struct sg_table sgt;
	struct scatterlist * sgl;
	int ret;
	tjob * tinfo = init_job(node, SLAVE_TEST, 2); 
	
	tinfo->amount = mode_2d ? DIV_ROUND_UP_ULL(glob_size, PAGE_SIZE) : 1;
	tinfo->osize = sizeof(unsigned long long);
	tinfo->isize = sizeof(unsigned long long);
	 
	tinfo->tname = __func__;
	
	pr_info("Entering %s, size: %s, amount: %u\n", tinfo->tname, hr_size, tinfo->amount);

	if ( !allocate_arrays (tinfo, 1, tinfo->isize, tinfo->osize) )
	    goto cfg_error;
	else
		pr_info("Succefully mapped dst and src dma addresses.\n");
	
    block = list_first_entry(&tinfo->data, tdata, elem);
	
	tinfo->config.direction = DMA_DEV_TO_DEV;
    tinfo->config.dst_addr_width = DMA_SLAVE_BUSWIDTH_8_BYTES;
    tinfo->config.dst_addr = block->dst_dma;
	tinfo->config.src_addr_width = DMA_SLAVE_BUSWIDTH_8_BYTES;
    tinfo->config.src_addr = block->src_dma;
	
	ret = dmaengine_slave_config(tinfo->parent->chan, &tinfo->config);
	
	/* All functions that run "device_control" must return the status of the channel, in this case DMA_SUCCESS */
	if (ret != DMA_SUCCESS)
		pr_warn("Strange status: %d\n", ret);
	else 
		pr_info("Slave config OK. (%d)\n", ret);

	*block->output = dvc_value; 
	
	if (tinfo->amount != 1) {
		
		/* 
		   This is actually a non-sense case for a real application, 
		   however it is implemented to test the algorithm of the inner function. 
		   
		*/
		
	    sg_alloc_table(&sgt, tinfo->amount, GFP_KERNEL);
		sgl = sgt.sgl;
		
		while (sgl) {
			
			sg_dma_address(sgl) = 0; /* Ignored for DMA_DEV_TO_DEV*/
			sg_dma_len(sgl) = PAGE_SIZE;
			
		    sgl = sg_next(sgl);
		}

	    tinfo->tx_desc = dmaengine_prep_slave_sg(tinfo->parent->chan,
												 sgt.sgl,
												 tinfo->amount,
												 DMA_DEV_TO_DEV,
												 flags);
		
		sg_free_table(&sgt);
		
	} else 
		tinfo->tx_desc = dmaengine_prep_slave_single(tinfo->parent->chan,
													 0, /* Ignored for DMA_DEV_TO_DEV*/
													 ALIGN(glob_size, sizeof(unsigned long long)),
													 DMA_DEV_TO_DEV,
													 flags);
	
	
	if (!submit_transaction(tinfo))
		goto cfg_error;
	
	return true;
	
 cfg_error:
	
	pr_err("Configuration error.");
	
	block = list_first_entry(&tinfo->data, tdata, elem);
	
	dma_free_coherent(tinfo->parent->chan->device->dev, tinfo->isize, block->input, block->dst_dma);
	dma_free_coherent(tinfo->parent->chan->device->dev, tinfo->osize, block->output, block->src_dma);
	
	list_del(&block->elem);
	kfree(block);
	
	return false;
}

bool do_dma_slave_sg ( telem * node ) { 
	
	return
		do_slave_dev_to_mem ( node ) &&
		do_slave_mem_to_dev ( node ) &&
		do_slave_dev_to_dev ( node );
}
