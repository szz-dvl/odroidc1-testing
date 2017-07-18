#include "dmatest.h"

bool do_dma_interrupt ( telem * node )
{
	unsigned long flags = 0;
	tjob * tinfo = init_job(node, DMA_IRQ, 0);
	
	tinfo->tname = __func__;
	
	tinfo->tx_desc = dmaengine_prep_dma_interrupt (tinfo->parent->chan, flags);
	
	if (!tinfo->tx_desc)
	    return false;
	
	if (!submit_transaction(tinfo))
		return false;
	
	return true;
}; 
