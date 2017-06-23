#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <asm/uaccess.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/irqreturn.h>
#include <linux/dmaengine.h>
#include <linux/dma-mapping.h>
#include <linux/kthread.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/scatterlist.h>

typedef enum test_type {
	
    DMA_SLAVE_SG,
	DMA_SCAT_GATH,
	DMA_CYCL,
	DMA_ILEAVED,
	DMA_IRQ,
	DMA_MCPY,
	DMA_MSET,
	ALL,

} ttype;

typedef struct test_data {
	
	struct list_head elem;
	
	/* DMA config fields */
    dma_addr_t src_dma;
	dma_addr_t dst_dma;
	
	/* Data fields */
	unsigned long long * input;
	unsigned long long * output;
	
} tdata;

typedef struct test_elem {
	
	struct list_head elem;
	struct mutex lock;
	struct dma_chan * chan;
	
	/* Data fields */ 
	struct list_head data;
	
	unsigned int osize;
	unsigned int isize;
	unsigned int amount;

	unsigned int tnum;
	int subt;

	dma_cookie_t tx_cookie;
	struct dma_async_tx_descriptor * tx_desc;
	struct dma_slave_config config;
	struct task_struct * thread;
	
	unsigned long stime;
	
} telem;

bool allocate_arrays (telem * tinfo, uint amount, uint isize, uint osize);
bool finish_transaction ( void * tinfo );
bool submit_transaction ( telem * tinfo );

/* Slave_SG */
bool do_slave_dev_to_mem ( telem * tinfo );
bool do_slave_mem_to_dev ( telem * tinfo );
bool do_slave_dev_to_dev ( telem * tinfo );
bool do_dma_slave_sg ( telem * tinfo );

/* Interleaved */
bool do_interleaved_mem_to_mem ( telem * tinfo );
bool do_interleaved_dev_to_mem ( telem * tinfo );
bool do_interleaved_mem_to_dev ( telem * tinfo );
bool do_interleaved_dev_to_dev ( telem * tinfo );
bool do_dma_ileaved ( telem * tinfo );

/* Cyclic */
bool do_cyclic_dev_to_mem ( telem * tinfo );
bool do_cyclic_dev_to_dev ( telem * tinfo );
bool do_cyclic_mem_to_dev ( telem * tinfo );
bool do_cyclic_mem_to_mem ( telem * tinfo );
bool do_dma_cyclic ( telem * tinfo );

/* DMA_SG: */
bool do_dma_scatter_gather ( telem * tinfo );

/* DMA_MemCopy: */
bool do_dma_memcpy ( telem * tinfo );

/* DMA_MemSet: */
bool do_dma_memset ( telem * tinfo );

/* DMA_Interrupt: */
bool do_dma_interrupt ( telem * tinfo ); /* Don't know how to do this ...*/

/* Parameters ofered in debugfs */
extern unsigned int dvc_value, verbose;
extern bool async_mode, mode_2d;
extern unsigned long long glob_size;

/* Shared vars */
extern char hr_size [32];
