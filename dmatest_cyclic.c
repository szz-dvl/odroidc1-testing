#include "dmatest.h"

void cyclic_callback ( void * job ) {

	tjob * tinfo = (tjob *) job;
	
	pr_info("Cyclic callback, period done in %u nanoseconds.\n", jiffies_to_usecs(jiffies - tinfo->stime));
	
	tinfo->stime = jiffies;
}

static bool do_cyclic_mem_to_dev_dev_to_mem ( telem * node, bool dire ) {

   	unsigned long flags = 0;
	tdata * block;
	int ret, i;
	tjob * tinfo = init_job(node, DMA_CYCL, dire ? 1 : 2); 

	tinfo->real_size = ALIGN(glob_size, sizeof(unsigned long long));
	tinfo->amount = !(tinfo->real_size % PAGE_SIZE) ? DIV_ROUND_UP_ULL(tinfo->real_size, PAGE_SIZE) : 1;
	
	tinfo->osize = dire ? sizeof(unsigned long long) : tinfo->real_size;
	tinfo->isize = dire ? tinfo->real_size : sizeof(unsigned long long);

	tinfo->tname = __func__;
	
	pr_info("%u >> Entering %s, size: %s, periods: %u\n", tinfo->parent->id, tinfo->tname, hr_size, tinfo->amount);

	if ( !allocate_arrays (tinfo, 1, tinfo->isize, tinfo->osize) )
	    goto cfg_error;
	else
		pr_info("%u >> Succefully mapped dst and src dma addresses.\n", tinfo->parent->id);
	
    block = list_first_entry(&tinfo->data, tdata, elem);

	if (dire) {
		
		tinfo->config.direction = DMA_DEV_TO_MEM;
		tinfo->config.src_addr_width = DMA_SLAVE_BUSWIDTH_8_BYTES;
		tinfo->config.src_addr = block->src_dma;
		
		*block->output = dvc_value;
		
	} else {

		tinfo->config.direction = DMA_MEM_TO_DEV;
		tinfo->config.dst_addr_width = DMA_SLAVE_BUSWIDTH_8_BYTES;
		tinfo->config.dst_addr = block->dst_dma;
		
		for (i = 0; i < tinfo->osize /sizeof(unsigned long long); i++)
			block->output[i] = dvc_value + i;
	}
	
	ret = dmaengine_slave_config(tinfo->parent->chan, &tinfo->config);
	
	/* All functions that run "device_control" must return the status of the channel, in this case DMA_SUCCESS */
	if (ret != DMA_SUCCESS)
		pr_warn("%u >> Strange status: %d\n", tinfo->parent->id, ret);
	else 
		pr_info("%u >> Slave config OK. (%d)\n", tinfo->parent->id, ret);
	
	tinfo->tx_desc = dmaengine_prep_dma_cyclic(tinfo->parent->chan,
											   dire ? block->dst_dma : block->src_dma, /* Ignored for DMA_DEV_TO_DEV*/
											   tinfo->real_size,
											   !(tinfo->real_size % PAGE_SIZE) ? PAGE_SIZE : tinfo->real_size,
											   dire ? DMA_DEV_TO_MEM : DMA_MEM_TO_DEV,
											   flags);
	
	if (!submit_transaction(tinfo))
		goto cfg_error;
	
	return true;
	
 cfg_error:
	
	pr_err("%u >> Configuration error.", tinfo->parent->id);
	
	block = list_first_entry_or_null(&tinfo->data, tdata, elem);
	
	if (block) {
		
		dma_free_coherent(tinfo->parent->chan->device->dev, tinfo->isize, block->input, block->dst_dma);
		dma_free_coherent(tinfo->parent->chan->device->dev, tinfo->osize, block->output, block->src_dma);
		
		list_del(&block->elem);
		kfree(block);
		
	}
	
	return false;	
	
}

bool do_cyclic_mem_to_mem_dev_to_dev ( telem * node, bool dire )
{
	unsigned long flags = 0;
	tdata * block;
	int ret, i;
	tjob * tinfo = init_job(node, DMA_CYCL, dire ? 3 : 0);
	
	tinfo->real_size = ALIGN(glob_size, sizeof(unsigned long long));
	tinfo->amount = !(tinfo->real_size % PAGE_SIZE) ? DIV_ROUND_UP_ULL(tinfo->real_size, PAGE_SIZE) : 1;
	
	tinfo->osize = dire ? sizeof(unsigned long long) : tinfo->real_size;
	tinfo->isize = dire ? sizeof(unsigned long long) : tinfo->real_size;
	
	tinfo->tname = __func__;
	
	pr_info("%u >> Entering %s, size: %s, periods: %u\n", tinfo->parent->id, tinfo->tname, hr_size, tinfo->amount);

	if ( !allocate_arrays (tinfo, 1, tinfo->isize, tinfo->osize) )
	    goto cfg_error;
	else
		pr_info("%u >> Succefully mapped dst and src dma addresses.\n", tinfo->parent->id);
	
    block = list_first_entry(&tinfo->data, tdata, elem);

	tinfo->config.direction = dire ? DMA_DEV_TO_DEV : DMA_MEM_TO_MEM;
	
	/* Careful here, direction (the global parameter), not dire */
	if (direction) {
		
		tinfo->config.src_addr_width = DMA_SLAVE_BUSWIDTH_8_BYTES;
		tinfo->config.src_addr = block->src_dma;
		
	} else {
	
		tinfo->config.dst_addr_width = DMA_SLAVE_BUSWIDTH_8_BYTES;
		tinfo->config.dst_addr = block->dst_dma;
		
	}

	if (dire)
		*block->output = dvc_value;
	else {

		for (i = 0; i < tinfo->osize /sizeof(unsigned long long); i++)
			block->output[i] = dvc_value + i; 
		
	}
	
	ret = dmaengine_slave_config(tinfo->parent->chan, &tinfo->config);
	
	/* All functions that run "device_control" must return the status of the channel, in this case DMA_SUCCESS */
	if (ret != DMA_SUCCESS)
		pr_warn("%u >> Strange status: %d\n", tinfo->parent->id, ret);
	else 
		pr_info("%u >> Slave config OK. (%d)\n", tinfo->parent->id, ret);

	tinfo->tx_desc = dmaengine_prep_dma_cyclic(tinfo->parent->chan,
											   direction ? block->dst_dma : block->src_dma, /* Ignored for DMA_DEV_TO_DEV*/
											   tinfo->real_size,
											   !(tinfo->real_size % PAGE_SIZE) ? PAGE_SIZE : tinfo->real_size,
											   dire ? DMA_DEV_TO_DEV : DMA_MEM_TO_MEM,
											   flags);
	
	if (!submit_transaction(tinfo))
		goto cfg_error;
	
	return true;
	
 cfg_error:
	
	pr_err("%u >> Configuration error.", tinfo->parent->id);
	
	block = list_first_entry_or_null(&tinfo->data, tdata, elem);
	
	if (block) {
		
		dma_free_coherent(tinfo->parent->chan->device->dev, tinfo->isize, block->input, block->dst_dma);
		dma_free_coherent(tinfo->parent->chan->device->dev, tinfo->osize, block->output, block->src_dma);
		
		list_del(&block->elem);
		kfree(block);
		
	}
	
	return false;
}

bool do_cyclic_mem_to_mem ( telem * node )
{
	return do_cyclic_mem_to_mem_dev_to_dev ( node, false ); 
}

bool do_cyclic_dev_to_mem ( telem * node )
{
	return do_cyclic_mem_to_dev_dev_to_mem ( node, true );
}

bool do_cyclic_mem_to_dev ( telem * node )
{
	return do_cyclic_mem_to_dev_dev_to_mem ( node, false );	
}

bool do_cyclic_dev_to_dev ( telem * node )
{
	return do_cyclic_mem_to_mem_dev_to_dev ( node, true );
}

bool do_dma_cyclic ( telem * node )
{
	return
		do_cyclic_dev_to_mem ( node ) &&
		do_cyclic_dev_to_dev ( node ) &&
		do_cyclic_mem_to_dev ( node ) &&
		do_cyclic_mem_to_mem ( node );
};
