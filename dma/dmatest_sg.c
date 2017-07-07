#include "dmatest.h"

bool do_dma_scatter_gather ( telem * node )
{
	return false;
};


/* 
   Maybe it would be nice to split this one to have dedicated tests 
   for asimetric transactions with sgents of diferents sizes for src and dst 
   such as:

   src: |====================| |==========================|
   dst: |=========| |=====| |========| |==================|
   
   src: |=========| |=====| |========| |==================|
   dst: |====================| |==========================| 

   [ . . . ]
   
   Or those achivable with interleaved:

   src: |===================================================|
   dst: |======| |======| |======| |======| |======| |======|
   
   or viceversa.

   etc, etc.

   Whatever the final implementation became we need to have in mind that there are 
   several scenarios here.
   
*/
