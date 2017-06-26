#include "dmatest.h"

bool do_cyclic_dev_to_mem ( telem * node )
{
	return false;
}

bool do_cyclic_dev_to_dev ( telem * node )
{
	return false;
}

bool do_cyclic_mem_to_dev ( telem * node )
{
	return false;
}

bool do_cyclic_mem_to_mem ( telem * node )
{
	return false;
}

bool do_dma_cyclic ( telem * node )
{
	return
		do_cyclic_dev_to_mem ( node ) &&
		do_cyclic_dev_to_dev ( node ) &&
		do_cyclic_mem_to_dev ( node ) &&
		do_cyclic_mem_to_mem ( node );
};
