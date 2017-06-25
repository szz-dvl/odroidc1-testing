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
	ALL_TESTS,
	ISSUE_JOBS,
	TERMINATE_NODE,

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

	uint id;

	spinlock_t lock;
	
	struct list_head jobs;
	struct list_head elem;
	
	struct dma_chan * chan;

	unsigned int cmd;
	int args;
	
	unsigned int batch_size;
	unsigned int pending;
	
} telem;

typedef struct test_job {

	struct list_head elem;

	telem * parent;
	const char * tname;
	
	unsigned int osize;
	unsigned int isize;
	unsigned int amount;
	
	/* Data fields */ 
	struct list_head data;

	dma_cookie_t tx_cookie;
	struct dma_async_tx_descriptor * tx_desc;
	struct dma_slave_config config;

	unsigned int tnum;
	int subt;
	
	unsigned long stime;

	bool async;
	
} tjob;

bool allocate_arrays (tjob * tinfo, uint amount, uint isize, uint osize);
bool submit_transaction ( tjob * tinfo );

/* Slave_SG */
bool do_slave_dev_to_mem ( tjob * tinfo );
bool do_slave_mem_to_dev ( tjob * tinfo );
bool do_slave_dev_to_dev ( tjob * tinfo );
bool do_dma_slave_sg ( tjob * tinfo );

/* Interleaved */
bool do_interleaved_mem_to_mem ( tjob * tinfo );
bool do_interleaved_dev_to_mem ( tjob * tinfo );
bool do_interleaved_mem_to_dev ( tjob * tinfo );
bool do_interleaved_dev_to_dev ( tjob * tinfo );
bool do_dma_ileaved ( tjob * tinfo );

/* Cyclic */
bool do_cyclic_dev_to_mem ( tjob * tinfo );
bool do_cyclic_dev_to_dev ( tjob * tinfo );
bool do_cyclic_mem_to_dev ( tjob * tinfo );
bool do_cyclic_mem_to_mem ( tjob * tinfo );
bool do_dma_cyclic ( tjob * tinfo );

/* DMA_SG: */
bool do_dma_scatter_gather ( tjob * tinfo );

/* DMA_MemCopy: */
bool do_dma_memcpy ( tjob * tinfo );

/* DMA_MemSet: */
bool do_dma_memset ( tjob * tinfo );

/* DMA_Interrupt: */
bool do_dma_interrupt ( tjob * tinfo ); /* Don't know how to do this ...*/

/* Parameters ofered in debugfs */
extern unsigned int dvc_value, verbose;
extern bool async_mode, mode_2d;
extern unsigned long long glob_size;

/* Shared vars */
extern char hr_size [32];
