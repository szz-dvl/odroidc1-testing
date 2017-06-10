//#include <linux/moduleparam.h>
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

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("S805 Dmaengine tester");
MODULE_AUTHOR("szz");

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

static unsigned int max_chann = 4;
module_param(max_chann, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(max_chann, "Maximum number of dma channels available.");

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

static int dev_open ( struct inode * inod, struct file * file );
static ssize_t dev_receive ( struct file * file, const char *buff, size_t len, loff_t * off );
static int dev_release ( struct inode * inod, struct file * file );
static int run_test ( void * tst_num );
static bool do_slave_dev_to_mem ( telem * tinfo );
static bool do_interleaved_mem_to_mem ( telem * tinfo );
static bool do_slave_mem_to_dev ( telem * tinfo );
static bool do_slave_dev_to_dev ( telem * tinfo );
static telem * get_free_chann ( void );
static bool register_debugfs ( void );
static bool allocate_arrays (telem * tinfo, uint amount, uint isize, uint osize);

static struct file_operations fops = {
	.write = dev_receive,
	.open = dev_open,
	.release = dev_release
};

static int dma_capabilities [] = { DMA_INTERLEAVE, DMA_SLAVE };
LIST_HEAD(test_list);

static unsigned int major, dvc_value, fifo_size = FIFO_SIZE, verbose = 1, glob_amount = 1;
static bool async_mode = true;

struct dentry *root;

static bool register_debugfs (void) {

	struct dentry *d;
	
	root = debugfs_create_dir("dmatest", NULL);	
	if (!root || IS_ERR(root))
		goto err_reg;
	
	d = debugfs_create_u32("major", S_IRUGO, root, (u32 *)&major);
	if (IS_ERR_OR_NULL(d))
	    goto err_reg;
	
	d = debugfs_create_u32("glob_amount", S_IRUGO | S_IWUSR, root, (u32 *)&glob_amount);
	if (IS_ERR_OR_NULL(d))
	    goto err_reg;

	d = debugfs_create_u32("dvc_value", S_IRUGO | S_IWUSR, root, (u32 *)&dvc_value);
	if (IS_ERR_OR_NULL(d))
	    goto err_reg;
	
	d = debugfs_create_u32("fifo_size", S_IRUGO | S_IWUSR, root, (u32 *)&fifo_size);
	if (IS_ERR_OR_NULL(d))
	    goto err_reg;
	
	d = debugfs_create_u32("verbose", S_IRUGO | S_IWUSR, root, (u32 *)&verbose);
	if (IS_ERR_OR_NULL(d))
	    goto err_reg;
	
	d = debugfs_create_bool("async_mode", S_IRUGO | S_IWUSR, root, (u32 *)&async_mode);
	if (IS_ERR_OR_NULL(d))
	    goto err_reg;
	
	return true;
	
 err_reg:
	debugfs_remove_recursive(root);
	return false;
}

static int dev_open ( struct inode * inod, struct file * file ) {

	return 0;

}

static ssize_t dev_receive ( struct file * file, const char *buff, size_t len, loff_t * off ) {
	
    unsigned long res;
	
	if (!kstrtoul(buff, 10, &res)) {
		
		telem * node = get_free_chann();
		node->tnum = res;
		node->thread = kthread_run(run_test,
								   node,
								   "dmatest-worker");	
	} else
		pr_err("Invalid test receieved: %s\n", buff);
	
	return len;

}

static int dev_release ( struct inode * inod, struct file * file ) {

	return 0;

}

static int my_callback(void * args) {

	telem * tinfo = (telem *) args;
	tdata * block, * temp;
	int i, j = 0;
	
	if (tinfo->chan->completed_cookie) {
		
		pr_info("Callback: Moved: %u Bytes in %u nanoseconds.\n", (tinfo->osize * tinfo->amount * sizeof(unsigned long long)), jiffies_to_usecs(jiffies - tinfo->stime));

		list_for_each_entry_safe (block, temp, &tinfo->data, elem) {
			
			if (block->dst_dma) {

				if (verbose >= 2) {

					pr_info("Block %u [%p][0x%08x]: \n", j, block->input, block->dst_dma);
				
					for (i = 0; i < tinfo->isize; i++)
						pr_info("%03d: %03llu, 0x%08llx\n", i, block->input[i], block->input[i]);
				}

				dma_free_coherent(tinfo->chan->device->dev, tinfo->isize * sizeof(unsigned long long), block->input, block->dst_dma);
			}
			
			dma_free_coherent(tinfo->chan->device->dev, tinfo->osize * sizeof(unsigned long long), block->output, block->src_dma);
			list_del(&block->elem);
			kfree(block);
			
			j ++;
		}
		
	} else 
		pr_info("Callback: Bad cookie!\n");
	
	return IRQ_HANDLED;
}

static bool allocate_arrays (telem * tinfo, uint amount, uint isize, uint osize) {

	/* Either @osize or @isize must evaluate to true here (> 0). */
	
	uint i;
	tdata * block, * temp;
	
	for (i = 0; i < amount; i++) {
		
	    block = (tdata *) kzalloc(sizeof(tdata), GFP_KERNEL);	

		if (isize) {

			block->input = dma_alloc_coherent(tinfo->chan->device->dev,
											  isize * sizeof(unsigned long long),
											  &block->dst_dma,
											  GFP_ATOMIC | __GFP_ZERO);

			if (dma_mapping_error(tinfo->chan->device->dev, block->dst_dma)) 
				goto map_error;
		}
		
		if (osize) {

			block->output = dma_alloc_coherent(tinfo->chan->device->dev,
											   osize * sizeof(unsigned long long),
											   &block->src_dma,
											   GFP_ATOMIC | __GFP_ZERO);
			
			if (dma_mapping_error(tinfo->chan->device->dev, block->src_dma)) 
				goto map_error;
		}
	  
		list_add_tail(&block->elem, &tinfo->data);
	}
	
	return true;
	
 map_error:
    pr_err("Error mapping DMA addresses.");
	
    list_for_each_entry_safe(block, temp, &tinfo->data, elem) {

		if (block->input)
			dma_free_coherent(tinfo->chan->device->dev, isize * sizeof(unsigned long long), block->input, block->dst_dma);
		
		if (block->output)
			dma_free_coherent(tinfo->chan->device->dev, osize * sizeof(unsigned long long), block->output, block->src_dma);
		
		list_del(&block->elem);
		kfree(block);
	}
	
	return false;
	
}

static bool do_slave_dev_to_mem (telem * tinfo) {
    
	unsigned long flags = 0;
	tdata * block, * temp;
	int ret, i, j = 0;
		
	tinfo->amount = glob_amount;
	tinfo->isize = fifo_size;
	tinfo->osize = 1;
	
	if ( !allocate_arrays (tinfo, tinfo->amount, tinfo->isize, tinfo->osize) )
	    goto cfg_error;
	else
		pr_info("Succefully mapped dst and src dma addresses.\n");
	
	list_for_each_entry (block, &tinfo->data, elem) {
		
		for (i = 0; i < tinfo->osize; i++)
			block->output[i] = dvc_value; 
		
		block->config.direction = DMA_DEV_TO_MEM;
		block->config.src_addr_width = DMA_SLAVE_BUSWIDTH_8_BYTES;
		block->config.src_addr = block->src_dma;
		
		ret = dmaengine_slave_config(tinfo->chan, &block->config);
		
		/* All functions that run "device_control" must return the status of the channel, in this case DMA_SUCCESS */
		if (ret != DMA_SUCCESS)
			pr_warn("Strange status: %d\n", ret);
		else 
			pr_info("Slave config OK. (%d)\n", ret);
		
		block->tx_desc = dmaengine_prep_slave_single(tinfo->chan,
													 block->dst_dma,
													 tinfo->isize * sizeof(unsigned long long),
													 DMA_DEV_TO_MEM,
													 flags);
		if(!block->tx_desc) {
			
			pr_err("Unable to get descriptor\n");
			goto cfg_error;
			
		} else
			pr_info("Got descriptor: %pB\n", block->tx_desc);
		
		block->tx_desc->callback = async_mode ? (void *) &my_callback : NULL;
		block->tx_desc->callback_param = async_mode ? (void *) tinfo : NULL;

		block->tx_cookie = dmaengine_submit(block->tx_desc);
		
		if(block->tx_cookie < 0) 
			pr_err("Error submitting transaction: %d\n", block->tx_cookie);
		else
			pr_info("Cookie submitted: %d\n", block->tx_cookie);
	}

	tinfo->stime = jiffies;
	dma_async_issue_pending(tinfo->chan);

	if (!async_mode) {

		list_for_each_entry_safe (block, temp, &tinfo->data, elem) {

			dma_wait_for_async_tx(block->tx_desc);

			if (verbose >= 2) {
				
				pr_info("Block %u [%p][0x%08x]: \n", j, block->input, block->dst_dma);
				
				for (i = 0; i < tinfo->isize; i++)
					pr_info("%03d: %03llu, 0x%08llx\n", i, block->input[i], block->input[i]);
			}
			
			dma_free_coherent(tinfo->chan->device->dev, tinfo->isize * sizeof(unsigned long long), block->input, block->dst_dma);
			dma_free_coherent(tinfo->chan->device->dev, tinfo->osize * sizeof(unsigned long long), block->output, block->src_dma);
			list_del(&block->elem);
			kfree(block);
			
			j++;
		}

		pr_info("Transcation finished, Moved %u Bytes in %u nanoseconds.\n", (tinfo->osize * tinfo->amount * sizeof(unsigned long long)), jiffies_to_usecs(jiffies - tinfo->stime));
	}
	
	return true;
	
 cfg_error:
	
	pr_err("Configuration error.");
	
    list_for_each_entry_safe(block, temp, &tinfo->data, elem) {
		
		dma_free_coherent(tinfo->chan->device->dev, tinfo->isize * sizeof(unsigned long long), block->input, block->dst_dma);
		dma_free_coherent(tinfo->chan->device->dev, tinfo->osize * sizeof(unsigned long long), block->output, block->src_dma);
		list_del(&block->elem);
		kfree(block);
	}
	
	return false;
}

static bool do_interleaved_mem_to_mem (telem * tinfo) {
	
    struct dma_interleaved_template *xt;
	unsigned long flags = 0;
	tdata * block, * temp;
    uint last_icg = 0;
	int i, j = 0;
	
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
		    15;//last_icg;
		
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
		
		dma_wait_for_async_tx(temp->tx_desc);
		
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

static bool do_slave_mem_to_dev (telem * tinfo) {

	return false;
}

static bool do_slave_dev_to_dev (telem * tinfo) { /* A lo loco con el moco ...*/

	return false;
}

static int run_test (void * node_ptr) {
	
	telem * node = (telem *) node_ptr;
	int ret;
	
	pr_info("DVC_VALUE: %u\n", dvc_value);
	pr_info("FIFO_SIZE: %u\n", fifo_size);
	pr_info("GLOB_AMOUNT: %u\n", glob_amount);
	pr_info("ASYNC_MODE: %u\n", async_mode);
	
	switch (node->tnum) 
		{
		case DEV_2_MEM:
			{
				ret = do_slave_dev_to_mem (node);
			}
			break;;
		case MEM_2_DEV:
			{
				ret =  do_slave_mem_to_dev (node);
			}
			break;;
		case DEV_2_DEV:
			{ 
				ret = do_slave_dev_to_dev (node);
			}
			break;;
		case MEM_2_MEM:
			{ 
				ret = do_interleaved_mem_to_mem (node);
			}
			break;;
		case ALL:
			{
				ret = false;
			}
			break;;
		default: 
			
			pr_err("Invalid test requested: %lu\n", node->tnum);
			ret = false;
			
		};
	
	if (!ret)
		pr_err("Error running test!\n");
	
	mutex_unlock(&node->lock);
	return ret;
}

static telem * get_free_chann (void) {

    telem *node;
	
	list_for_each_entry(node, &test_list, elem) {
		if (!mutex_is_locked(&node->lock)) {
			mutex_lock(&node->lock);
			return node;
		}
	}
	
	return NULL;
}

static int __init dmatest_init(void)
{
	dma_cap_mask_t mask;
	int i;
	
    get_random_bytes(&dvc_value, 32);
	
	major = register_chrdev(0, "dmatest", &fops);
	if ( major < 0 ) {
		
		pr_err("Char device registration failed.");
		goto err_gen;
		
	} else
		pr_info("Char device %d registered.\n", major);
	
    if (!register_debugfs()) {
		
		pr_err("Debugfs registration failed.");
		unregister_chrdev ( major, "dmatest" );
	    return -6;
		
	}
	
	dma_cap_zero(mask);
		
	for (i = 0; i < 2; i++)
		dma_cap_set(dma_capabilities[i], mask);
	
	for (i = 0; i < max_chann; i++) {
		
		telem * node = (telem *) kzalloc(sizeof(telem), GFP_KERNEL);

		if (node) {
			
			mutex_init(&node->lock);
			node->chan = dma_request_channel(mask, NULL, NULL);
			INIT_LIST_HEAD(&node->data);
			
			if (node->chan) 
				list_add_tail(&node->elem, &test_list);
			else
				break;
			
		} else {
			
			pr_err("Error allocating element %d.", i);
			break;
			
		}
	}
	
	if (i == 0) {
		
		pr_err("No channels availbale\n");
		goto err_gen;
		
	}
	
	return 0;
	
 err_gen:
	debugfs_remove_recursive( root );
	unregister_chrdev ( major, "dmatest" );
	return -6;

}

static void __exit dmatest_exit(void)
{

	telem * node;
	
	list_for_each_entry(node, &test_list, elem) {

		if (mutex_is_locked(&node->lock)) {
			
			kthread_stop(node->thread);
			mutex_unlock(&node->lock);
			
		}
		
		dma_release_channel ( node->chan );
	}
	
	unregister_chrdev ( major, "dmatest" );
	debugfs_remove_recursive(root);
	
	return;
}

module_init(dmatest_init);
module_exit(dmatest_exit);
