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
#include <linux/random.h>
#include <linux/kthread.h>
#include <linux/jiffies.h>

#define FIFO_SIZE               32
#define S805_DMA_MAX_SKIP       0xFFFF

#define WR(data, addr)  *(volatile unsigned long *)(addr)=data
#define RD(addr)        *(volatile unsigned long *)(addr)

typedef enum test_type {
	
	DEV_2_MEM,    /* dev write */
	MEM_2_DEV,    /* dev read */
    DEV_2_DEV,    /* some kind of protocol ?? */
	MEM_2_MEM,    /* m2m */
	ALL           /* All tests */

} ttype;

typedef struct test_data {
	
	struct list_head elem;
	
	/* DMA config fields */
    dma_addr_t src_dma;
	dma_addr_t dst_dma;
	dma_cookie_t tx_cookie;
	struct dma_slave_config config;
	struct dma_async_tx_descriptor * tx_desc;
	
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

	unsigned long tnum;
	struct task_struct * thread;
	
	unsigned long stime;
	
} telem;

bool allocate_arrays (telem * tinfo, uint amount, uint isize, uint osize);

bool do_slave_dev_to_mem ( telem * tinfo );
bool do_interleaved_mem_to_mem ( telem * tinfo );
bool do_slave_mem_to_dev ( telem * tinfo );
bool do_slave_dev_to_dev ( telem * tinfo );
int my_callback ( void * args );
	
/* Parameters ofered in debugfs */
static unsigned int dvc_value,
	fifo_size = FIFO_SIZE,
	verbose = 1,
	glob_amount = 1;

static bool async_mode = false;
