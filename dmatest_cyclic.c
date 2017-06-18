#include "dmatest.h"

bool do_cyclic_dev_to_mem ( telem * tinfo )
{
	return false;
}

bool do_cyclic_dev_to_dev ( telem * tinfo )
{
	return false;
}

bool do_cyclic_mem_to_dev ( telem * tinfo )
{
	return false;
}

bool do_cyclic_mem_to_mem ( telem * tinfo )
{
	return false;
}

bool do_dma_cyclic ( telem * tinfo )
{
	return
		do_cyclic_dev_to_mem ( tinfo ) &&
		do_cyclic_dev_to_dev ( tinfo ) &&
		do_cyclic_mem_to_dev ( tinfo ) &&
		do_cyclic_mem_to_mem ( tinfo );
};
