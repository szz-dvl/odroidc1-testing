#include "dmatest.h"

extern unsigned int dvc_value, fifo_size, verbose, glob_amount;
extern bool async_mode;

bool do_interleaved_mem_to_mem (telem * tinfo) {
	
    struct dma_interleaved_template *xt;
	unsigned long flags = 0;
	tdata * block, * temp;
    uint last_icg = 0;
	int i, j = 0;
	enum dma_status to;
	
	xt = kzalloc(sizeof(struct dma_interleaved_template) +
				 glob_amount * sizeof(struct data_chunk), GFP_KERNEL);
	
	if (!xt) {
		
		kfree(xt);
		return false;
		
	}
	
	tinfo->amount = glob_amount;
	tinfo->isize = fifo_size * glob_amount;
	tinfo->osize = fifo_size;
	
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
	//use icg = 0 here to mix 1D and 2D move!
	xt->src_sgl = true;
	xt->dst_sgl = false;
	xt->numf = 1; 
	xt->frame_size = tinfo->amount;
	
	list_for_each_entry (block, &tinfo->data, elem) {
		
		for (i = 0; i < tinfo->osize; i++)
			block->output[i] = dvc_value + i + j; 

		xt->sgl[j].size = tinfo->osize * sizeof(unsigned long long);
		xt->sgl[j].icg = !list_is_last(&block->elem, &tinfo->data) ?
			list_next_entry(block, elem)->src_dma - (block->src_dma + xt->sgl[j].size) :
		    last_icg;
		
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
	
    temp->tx_desc->callback = async_mode ? (void *) &my_callback : NULL;
    temp->tx_desc->callback_param = async_mode ? (void *) tinfo : NULL;
	
	temp->tx_cookie = dmaengine_submit(temp->tx_desc);
	
	if (temp->tx_cookie < 0) {
		pr_err("Error submitting transaction: %d\n", temp->tx_cookie);
	 	goto cfg_error;
	} else
		pr_info("Cookie submitted: %d\n", temp->tx_cookie);
	
	tinfo->stime = jiffies;
	dma_async_issue_pending(tinfo->chan);
	
	if (!async_mode) {
		
		to = dma_wait_for_async_tx(temp->tx_desc);

		if (to != DMA_ERROR)
			pr_info("Transcation finished, Moved %u Bytes in %u nanoseconds.\n", (tinfo->osize * tinfo->amount * sizeof(unsigned long long)), jiffies_to_usecs(jiffies - tinfo->stime));
		
		if (verbose >= 2) {
			
			pr_info("Block [%p][0x%08x]: \n", temp->input, temp->dst_dma);
			
			for (i = 0; i < tinfo->isize; i++)
				pr_info("%03d: %03llu, 0x%08llx\n", i, temp->input[i], temp->input[i]);
		}
		
		dma_free_coherent(tinfo->chan->device->dev, tinfo->isize * sizeof(unsigned long long), temp->input, temp->dst_dma);
		dma_free_coherent(tinfo->chan->device->dev, tinfo->osize * sizeof(unsigned long long), temp->output, temp->src_dma);
		list_del(&temp->elem);
		kfree(temp);
		
		list_for_each_entry_safe(block, temp, &tinfo->data, elem) {
			
			dma_free_coherent(tinfo->chan->device->dev, tinfo->osize * sizeof(unsigned long long), block->output, block->src_dma);
			list_del(&block->elem);
			kfree(block);	
		}
	}

	kfree(xt);
	
	return true;
	
 cfg_error:
	pr_err("Configuration error.");
	
	list_for_each_entry_safe(block, temp, &tinfo->data, elem) {
		
		if (block->dst_dma)
			dma_free_coherent(tinfo->chan->device->dev, tinfo->isize * sizeof(unsigned long long), block->input, block->dst_dma);
		
		dma_free_coherent(tinfo->chan->device->dev, tinfo->osize * sizeof(unsigned long long), block->output, block->src_dma);
		list_del(&block->elem);
		kfree(block);
	}

	kfree(xt);
	
	return false;
}
