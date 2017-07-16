#include "dmatest.h"

static bool do_slave_dev_to_mem_mem_to_dev ( telem * node, bool dire ) {
    
	unsigned long flags = 0;
	tdata * block, * temp;
    struct sg_table sgt;
	struct scatterlist * sgl;
	int ret, j, i;
	tjob * tinfo = init_job(node, DMA_SLAVE_SG, dire ? 1 : 2);

	tinfo->real_size = ALIGN(glob_size, sizeof(unsigned long long));
	tinfo->amount = mode_2d ? DIV_ROUND_UP_ULL(tinfo->real_size, PAGE_SIZE) : 1;
	tinfo->isize = dire ? (mode_2d ? PAGE_SIZE : tinfo->real_size) : sizeof(unsigned long long);
	tinfo->osize = dire ? sizeof(unsigned long long) : (mode_2d ? PAGE_SIZE : tinfo->real_size);
	
	tinfo->tname = dire ? "do_slave_dev_to_mem" : "do_slave_mem_to_dev";
	
	pr_info("%u >> Entering %s, size: %s, amount: %u\n", tinfo->parent->id, tinfo->tname, hr_size, tinfo->amount);
	
	if ( !allocate_arrays (tinfo, 1, tinfo->isize, tinfo->osize) )
	    goto cfg_error;
	else {
		
		if ( !allocate_arrays (tinfo, (tinfo->amount - 1), dire ? tinfo->isize : 0, dire ? 0 : tinfo->osize) )
			goto cfg_error;	
		else
			pr_info("%u >> Succefully mapped dst and src dma addresses.\n", tinfo->parent->id);
	}
	
    temp = list_first_entry(&tinfo->data, tdata, elem);
	
	tinfo->config.direction = dire ? DMA_DEV_TO_MEM : DMA_MEM_TO_DEV;

	if (dire) {

		tinfo->config.src_addr_width = DMA_SLAVE_BUSWIDTH_8_BYTES;
		tinfo->config.src_addr = temp->src_dma;
		*temp->output = dvc_value;
		
	} else {

		tinfo->config.dst_addr_width = DMA_SLAVE_BUSWIDTH_8_BYTES;
		tinfo->config.dst_addr = temp->dst_dma;
	}
	
	ret = dmaengine_slave_config(tinfo->parent->chan, &tinfo->config);
	
	/* All functions that run "device_control" must return the status of the channel, in this case DMA_SUCCESS */
	if (ret != DMA_SUCCESS)
		pr_warn("%u >> Strange status: %d\n", tinfo->parent->id, ret);
	else 
		pr_info("%u >> Slave config OK. (%d)\n", tinfo->parent->id, ret);
	
	if (tinfo->amount != 1) {
		
	    if(sg_alloc_table(&sgt, tinfo->amount, GFP_KERNEL))
			goto cfg_error;
		
		sgl = sgt.sgl;
		block = temp;
		temp = list_next_entry(block, elem);
		j = 0;
		
		while (sgl) {

			if (!dire) {
				
				for (i = 0; i < (tinfo->osize / sizeof(unsigned long long)); i++)
					block->output[i] = dvc_value + i + j;	
			}
			
			sg_dma_address(sgl) = dire ? block->dst_dma : block->src_dma;
			sg_dma_len(sgl) = dire ? tinfo->isize : tinfo->osize;
			
			if (verbose >= 2)
				pr_info("%u >> Block %d (0x%08x -> 0x%08x): size->%u, icg->%u\n", tinfo->parent->id, j, block->src_dma, block->dst_dma, sg_dma_len(sgl),
						(void *) temp != (void *) &tinfo->data ? dire ? (temp->dst_dma - (block->dst_dma + sg_dma_len(sgl))) : (temp->src_dma - (block->src_dma + sg_dma_len(sgl))) : 0);
			
		    sgl = sg_next(sgl);
			block = temp;
		    temp = list_next_entry(block, elem);  
			j++;
		}

	    tinfo->tx_desc = dmaengine_prep_slave_sg(tinfo->parent->chan,
												 sgt.sgl,
												 tinfo->amount,
												 dire ? DMA_DEV_TO_MEM : DMA_MEM_TO_DEV,
												 flags);
		
		sg_free_table(&sgt);
		
	} else 
		tinfo->tx_desc = dmaengine_prep_slave_single(tinfo->parent->chan,
													 dire ? temp->dst_dma : temp->src_dma,
													 dire ? tinfo->isize : tinfo->osize,
													 dire ? DMA_DEV_TO_MEM : DMA_MEM_TO_DEV,
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
}

bool do_slave_dev_to_mem ( telem * node ) {

	return do_slave_dev_to_mem_mem_to_dev ( node, true );
	
}

bool do_slave_mem_to_dev ( telem * node ) {

	return do_slave_dev_to_mem_mem_to_dev ( node, false );

}

bool do_slave_dev_to_dev ( telem * node ) { 
	
	unsigned long flags = 0;
	tdata * block;
	struct sg_table sgt;
	struct scatterlist * sgl;
	int ret;
	tjob * tinfo = init_job(node, DMA_SLAVE_SG, 3); 

	tinfo->real_size = ALIGN(glob_size, sizeof(unsigned long long));
	tinfo->amount = mode_2d ? DIV_ROUND_UP_ULL(glob_size, PAGE_SIZE) : 1;
	tinfo->osize = sizeof(unsigned long long);
	tinfo->isize = sizeof(unsigned long long);
	 
	tinfo->tname = __func__;
	
	pr_info("%u >> Entering %s, size: %s, amount: %u\n", tinfo->parent->id, tinfo->tname, hr_size, tinfo->amount);

	if ( !allocate_arrays (tinfo, 1, tinfo->isize, tinfo->osize) )
	    return false;
	else
		pr_info("%u >> Succefully mapped dst and src dma addresses.\n", tinfo->parent->id);
	
    block = list_first_entry(&tinfo->data, tdata, elem);
	
	tinfo->config.direction = DMA_DEV_TO_DEV;
    tinfo->config.dst_addr_width = DMA_SLAVE_BUSWIDTH_8_BYTES;
    tinfo->config.dst_addr = block->dst_dma;
	tinfo->config.src_addr_width = DMA_SLAVE_BUSWIDTH_8_BYTES;
    tinfo->config.src_addr = block->src_dma;
	
	ret = dmaengine_slave_config(tinfo->parent->chan, &tinfo->config);
	
	/* All functions that run "device_control" must return the status of the channel, in this case DMA_SUCCESS */
	if (ret != DMA_SUCCESS)
		pr_warn("%u >> Strange status: %d\n", tinfo->parent->id, ret);
	else 
		pr_info("%u >> Slave config OK. (%d)\n", tinfo->parent->id, ret);

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
													 tinfo->real_size,
													 DMA_DEV_TO_DEV,
													 flags);
	
	
	if (!tinfo->tx_desc)
		goto cfg_error;
	
	if (!submit_transaction(tinfo))
		goto cfg_error;
	
	return true;
	
 cfg_error:
	
	pr_err("%u >> Configuration error.", tinfo->parent->id);
	

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
