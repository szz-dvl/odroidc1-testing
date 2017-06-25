#include "dmatest.h"

bool do_cyclic_dev_to_mem ( tjob * tinfo )
{
	return false;
}

bool do_cyclic_dev_to_dev ( tjob * tinfo )
{
	return false;
}

bool do_cyclic_mem_to_dev ( tjob * tinfo )
{
	return false;
}

bool do_cyclic_mem_to_mem ( tjob * tinfo )
{
	return false;
}

bool do_dma_cyclic ( tjob * tinfo )
{
	return
		do_cyclic_dev_to_mem ( tinfo ) &&
		do_cyclic_dev_to_dev ( tinfo ) &&
		do_cyclic_mem_to_dev ( tinfo ) &&
		do_cyclic_mem_to_mem ( tinfo );
};
