#include "dmatest.h"

static bool do_interleaved_dev_to_mem_mem_to_dev ( telem * node, bool dire )
{
    struct dma_interleaved_template *xt;
	unsigned long flags = 0;
	tdata * block, * temp;
    uint last_icg = 0;
	int i, j = 0;
	unsigned long array_size;
	tjob * tinfo = init_job(node, DMA_ILEAVED, dire ? 1 : 2);
	
	array_size = mode_2d ? (PAGE_SIZE + (sizeof(unsigned long long) * 4)) : PAGE_SIZE;
	tinfo->amount = mode_2d ? DIV_ROUND_UP_ULL(glob_size, array_size) : 1;
	
	tinfo->tname = dire ? "do_interleaved_dev_to_mem" : "do_interleaved_mem_to_dev";

	if (mode_2d)
		tinfo->real_size = tinfo->amount * array_size;
	
	pr_info("%u >> Entering %s, size: %s, amount: %u\n", tinfo->parent->id, tinfo->tname, hr_size, tinfo->amount);
	
	xt = kzalloc(sizeof(struct dma_interleaved_template) +
				 tinfo->amount * sizeof(struct data_chunk), GFP_KERNEL);
	
	if (!xt) 
		return false;
	
	tinfo->isize = dire ? (mode_2d ? array_size : glob_size) : sizeof(unsigned long long);
	tinfo->osize = dire ? sizeof(unsigned long long) : (mode_2d ? array_size : glob_size);
	
	if ( !allocate_arrays (tinfo, 1, tinfo->isize, tinfo->osize) )
		goto cfg_error;
	else {
		
		if ( !allocate_arrays (tinfo, (tinfo->amount - 1), dire ? tinfo->isize : 0, dire ? 0 : tinfo->osize) ) 
			goto cfg_error;
		else
			pr_info("%u >> Succefully mapped dst and src dma addresses.\n", tinfo->parent->id);
	}
	
	temp = list_first_entry(&tinfo->data, tdata, elem);
	
	xt->src_start = temp->src_dma;
	xt->dst_start = temp->dst_dma;
	xt->dir = dire ? DMA_DEV_TO_MEM : DMA_MEM_TO_DEV;
	xt->src_inc = dire ? false : true;
	xt->dst_inc = dire ? true : false;
	xt->src_sgl = dire ? false : (mode_2d ? true : false);
	xt->dst_sgl = dire ? (mode_2d ? true : false) : false;
	xt->numf = 1; /* Actually ignored in the driver, more info: "drivers/dma/s805_dmaengine.c" */
	xt->frame_size = tinfo->amount;

	if (dire)
		*temp->output = dvc_value;
		
	list_for_each_entry (block, &tinfo->data, elem) {

		if (!dire) {

			for (i = 0; i < (tinfo->osize / sizeof(unsigned long long)); i++)
				block->output[i] = dvc_value + i + j;

		}
		
		xt->sgl[j].size = dire ? tinfo->isize : tinfo->osize;
		xt->sgl[j].icg = !list_is_last(&block->elem, &tinfo->data) ?
			dire ? list_next_entry(block, elem)->dst_dma - (block->dst_dma + xt->sgl[j].size) :
			list_next_entry(block, elem)->src_dma - (block->src_dma + xt->sgl[j].size) :
		    last_icg;

		if (verbose >= 2)
			pr_info("%u >> Block %d (0x%08x -> 0x%08x): size->%u, icg->%u\n", tinfo->parent->id, j, block->src_dma, block->dst_dma, xt->sgl[j].size, xt->sgl[j].icg);
		
		last_icg = xt->sgl[j].icg;
		j++;
	}
	
    tinfo->tx_desc = dmaengine_prep_interleaved_dma(tinfo->parent->chan, xt, flags);

	if (!submit_transaction(tinfo))
		goto cfg_error;
	
	kfree(xt);
	
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
	
	kfree(xt);
	
	return false;
};

bool do_interleaved_mem_to_mem ( telem * node ) {
	
    struct dma_interleaved_template *xt;
	unsigned long flags = 0;
	tdata * block, * temp;
    uint last_icg = 0;
	int i, j = 0;
	unsigned long array_size;
	tjob * tinfo = init_job(node, DMA_ILEAVED, 0);
	
	array_size = mode_2d ? (PAGE_SIZE + (sizeof(unsigned long long) * 4)) : PAGE_SIZE;
	tinfo->amount = DIV_ROUND_UP_ULL(glob_size, array_size);

	tinfo->tname = __func__;

	if (mode_2d)
		tinfo->real_size = tinfo->amount * array_size;
	
	pr_info("%u >> Entering %s, size: %s, amount: %u\n", tinfo->parent->id, tinfo->tname, hr_size, tinfo->amount);
	
	xt = kzalloc(sizeof(struct dma_interleaved_template) +
				 tinfo->amount * sizeof(struct data_chunk), GFP_KERNEL);
	
	if (!xt) 
		return false;
	
	tinfo->isize = direction ? array_size * tinfo->amount : array_size;
	tinfo->osize = direction ? array_size : array_size * tinfo->amount;
	
	if ( !allocate_arrays (tinfo, 1, tinfo->isize, tinfo->osize) )
		goto cfg_error;
	else {
		
		if ( !allocate_arrays (tinfo, (tinfo->amount - 1), direction ? 0 : tinfo->isize, direction ? tinfo->osize : 0) ) 
			goto cfg_error;
		else
			pr_info("%u >> Succefully mapped dst and src dma addresses.\n", tinfo->parent->id);
	}

	temp = list_first_entry(&tinfo->data, tdata, elem);
	
	xt->src_start = temp->src_dma;
	xt->dst_start = temp->dst_dma;
	xt->dir = DMA_MEM_TO_MEM;
	xt->src_inc = true;
	xt->dst_inc = true;
	xt->src_sgl = direction ? true : false;
	xt->dst_sgl = direction ? false : true;
	xt->numf = 1; /* Actually ignored in the driver, more info: "drivers/dma/s805_dmaengine.c" */ 
	xt->frame_size = tinfo->amount;

	if (!direction) {

		for (i = 0; i < (tinfo->osize / sizeof(unsigned long long)); i++)
			temp->output[i] = dvc_value + i;
		
	}
	
	list_for_each_entry (block, &tinfo->data, elem) {
		
		if (direction) {

			for (i = 0; i < (tinfo->osize / sizeof(unsigned long long)); i++)
				block->output[i] = dvc_value + i + j; 
		}
		
		xt->sgl[j].size = direction ? tinfo->osize : tinfo->isize ;
		xt->sgl[j].icg = !list_is_last(&block->elem, &tinfo->data) ?
			direction ? list_next_entry(block, elem)->src_dma - (block->src_dma + xt->sgl[j].size) :
			list_next_entry(block, elem)->dst_dma - (block->dst_dma + xt->sgl[j].size) :
		    last_icg;

		if (verbose >= 2)
			pr_info("%u >> Block %d (0x%08x -> 0x%08x): size->%u, icg->%u\n", tinfo->parent->id, j, block->src_dma, block->dst_dma, xt->sgl[j].size, xt->sgl[j].icg);
		
		last_icg = xt->sgl[j].icg;
		j++;
	}
	
    tinfo->tx_desc = dmaengine_prep_interleaved_dma(tinfo->parent->chan, xt, flags);

	if (!submit_transaction(tinfo))
		goto cfg_error;
	
	kfree(xt);
	
	return true;
	
 cfg_error:
	pr_err("%u >> Configuration error.", tinfo->parent->id);
	
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

bool do_interleaved_dev_to_mem ( telem * node ) {

	return do_interleaved_dev_to_mem_mem_to_dev(node, true);

}

bool do_interleaved_mem_to_dev ( telem * node ) {

	return do_interleaved_dev_to_mem_mem_to_dev(node, false);
	
}

bool do_interleaved_dev_to_dev ( telem * node )
{
    struct dma_interleaved_template *xt;
	unsigned long flags = 0;
	tdata * block;
   	tjob * tinfo = init_job(node, DMA_ILEAVED, 3);
	
	tinfo->amount = 1;

	tinfo->tname = __func__;
	
	pr_info("%u >> Entering %s, size: %s, amount: %u\n", tinfo->parent->id, tinfo->tname, hr_size, tinfo->amount);
	
	xt = kzalloc(sizeof(struct dma_interleaved_template) +
				 tinfo->amount * sizeof(struct data_chunk), GFP_KERNEL);
	
	if (!xt) 
		return false;
	
	tinfo->isize = sizeof(unsigned long long);
	tinfo->osize = sizeof(unsigned long long);
	
	if ( !allocate_arrays (tinfo, 1, tinfo->isize, tinfo->osize) )
		goto cfg_error;
	else 
		pr_info("%u >> Succefully mapped dst and src dma addresses.\n", tinfo->parent->id);
			
	block = list_first_entry(&tinfo->data, tdata, elem);
	
	xt->src_start = block->src_dma;
	xt->dst_start = block->dst_dma;
	xt->dir = DMA_DEV_TO_DEV;
	xt->src_inc = false;
	xt->dst_inc = false;
	xt->src_sgl = false;
	xt->dst_sgl = false;
	xt->numf = 1; /* Actually ignored in the driver, more info: "drivers/dma/s805_dmaengine.c" */ 
	xt->frame_size = tinfo->amount;

	*block->output = dvc_value;

	xt->sgl[0].size = ALIGN(glob_size, sizeof(unsigned long long));
	xt->sgl[0].icg = 0; /* Ignored, 1D always for DMA_DEV_TO_DEV */
	
    tinfo->tx_desc = dmaengine_prep_interleaved_dma(tinfo->parent->chan, xt, flags);
	
	if (!submit_transaction(tinfo))
		goto cfg_error;
	
	kfree(xt);
	
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
	
	kfree(xt);
	
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
