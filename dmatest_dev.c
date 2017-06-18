//#include <linux/moduleparam.h>
#include "dmatest.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("S805 Dmaengine tester");
MODULE_AUTHOR("szz");

static unsigned int max_chann = 4;
module_param(max_chann, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(max_chann, "Maximum number of dma channels available.");

static int dev_open ( struct inode * inod, struct file * file );
static ssize_t dev_receive ( struct file * file, const char *buff, size_t len, loff_t * off );
static int dev_release ( struct inode * inod, struct file * file );
static telem * get_free_node ( void );
static bool register_debugfs ( void );
static int run_test ( void * tst_num );

static struct file_operations fops = {
	.write = dev_receive,
	.open = dev_open,
	.release = dev_release
};

static uint dma_capabilities [] = {

	DMA_SLAVE,
	DMA_INTERLEAVE,
	DMA_INTERRUPT,
	DMA_ASYNC_TX,
	DMA_CYCLIC,
	DMA_SG,
	DMA_MEMCPY,
	DMA_MEMSET
	
};

static dma_cap_mask_t mask;

LIST_HEAD(test_list);

static unsigned int major;

/* Default value for parameters */

unsigned int fifo_size = FIFO_SIZE;
unsigned int dvc_value = 100;
unsigned int verbose = 1;
unsigned int glob_amount = 1;

bool async_mode = true;

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
	
    unsigned int res;
	char * token;
	char * str = "";
	uint i = 0;
	telem * node = get_free_node();

	if ( node ) {

		strcpy(str, buff);
		
		while ((token = strsep(&str, ","))) {
			
			if (strcmp(token, "")) {
				
				if (!kstrtou32(token, 10, &res)) {
					
					switch (i) {
					case 0:
						node->tnum = res;
						break;;
					case 1:
						node->subt = (int) res;
						break;;
					default:
						pr_info("Extra parameter received: %u\n", res);
						break;;
					}
					
					i++;
					
				} else
					pr_err("Invalid test receieved: %s\n", token);
			}
		};
		
		pr_info("Running test %u (subtest: %d)\n", node->tnum, node->subt);
		
		node->thread = kthread_run ( run_test,
									 node,
									 "dmatest-worker" );
		
	} else
		pr_err("No free node available.\n");
	
	return len;
}

static int dev_release ( struct inode * inod, struct file * file ) {

	return 0;

}

int my_callback(void * args) {

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

	
	dma_release_channel ( tinfo->chan );
	
	return IRQ_HANDLED;
}

bool allocate_arrays (telem * tinfo, uint amount, uint isize, uint osize) {

	/* Either @osize or @isize must evaluate to true here (> 0). */
	
	uint i;
	tdata * block, * temp;
	
	for (i = 0; i < amount; i++) {
		
	    block = (tdata *) kzalloc(sizeof(tdata), GFP_KERNEL);	

		if (isize) {
			
			block->input = dma_zalloc_coherent(tinfo->chan->device->dev,
											   isize * sizeof(unsigned long long),
											   &block->dst_dma,
											   GFP_ATOMIC); /* GFP_KERNEL hits kernel BUG at mm/vmalloc.c:100 */
			
			if (dma_mapping_error(tinfo->chan->device->dev, block->dst_dma)) 
				goto map_error;
		}
		
		if (osize) {
			
			block->output = dma_zalloc_coherent(tinfo->chan->device->dev,
												osize * sizeof(unsigned long long),
												&block->src_dma,
											    GFP_ATOMIC);
			
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

static int run_test (void * node_ptr) {
	
	telem * node = (telem *) node_ptr;
	int ret = false;
	
	pr_info("DVC_VALUE: %u\n", dvc_value);
	pr_info("FIFO_SIZE: %u\n", fifo_size);
	pr_info("GLOB_AMOUNT: %u\n", glob_amount);
	pr_info("ASYNC_MODE: %s\n", async_mode ? "true" : "false");

	node->chan = dma_request_channel ( mask, NULL, NULL );

	/* 
	   To-Do: A bunch of things!! and add support for terminating cyclic transactions.  
	*/
	if (node->chan) {
		
		switch (node->tnum) 
			{

			case DMA_SLAVE_SG:
				{
					switch(node->subt) {
					case 0:
						ret = do_slave_dev_to_mem ( node );
						break;;
					case 1:
						ret = do_slave_mem_to_dev ( node );
						break;;
					case 2:
						ret = do_slave_dev_to_dev ( node );
						break;;
					default:
						ret = do_dma_slave_sg ( node );
					}
				}
				break;;
				
			case DMA_SCAT_GATH:
				{ 
					ret = do_dma_scatter_gather ( node );
				}
				break;;
				
			case DMA_CYCL:
				{
					switch(node->subt) {
					case 0:
						ret = do_cyclic_dev_to_mem ( node );
						break;;
					case 1:
						ret = do_cyclic_dev_to_dev ( node );
						break;;
					case 2:
						ret = do_cyclic_mem_to_dev ( node );
						break;;
					case 3:
						ret = do_cyclic_mem_to_mem ( node );
						break;;
					default:
						ret = do_dma_cyclic ( node );
					}
				}
				break;;

			case DMA_ILEAVED:
				{
					switch(node->subt) {
					case 0:
						ret = do_interleaved_mem_to_mem ( node );
						break;;
					case 1:
						ret = do_interleaved_dev_to_mem ( node );
						break;;
					case 2:
						ret = do_interleaved_mem_to_dev ( node );
						break;;
					case 3:
						ret = do_interleaved_dev_to_dev ( node );
						break;;
					default:
						ret = do_dma_cyclic ( node );
					}
					
				}
				break;;
				
			case DMA_IRQ:
				{ 
					ret = do_dma_interrupt ( node );
				}
				break;;

			case DMA_MCPY:
				{ 
					ret = do_dma_memcpy ( node );
				}
				break;;

			case DMA_MSET:
				{ 
					ret = do_dma_memset ( node );
				}
				break;;
				
			case ALL:
				{
					ret =
						do_dma_slave_sg ( node ) &&
						do_dma_cyclic ( node ) &&
						do_dma_interrupt ( node ) &&
						do_dma_ileaved ( node ) &&
						do_dma_scatter_gather ( node ) &&
						do_dma_memcpy ( node ) &&
						do_dma_memset ( node );	
				}
				break;;
				
			default: 
				
				pr_err("Invalid test requested: %u\n", node->tnum);
				ret = false;
				
			};
	
		if (!ret)
			pr_err("Error running test %u.\n", node->tnum);
		
		if (!async_mode)
			dma_release_channel ( node->chan );
		
	} else
		pr_err("No channel available.\n");

    node->subt = -1;
	mutex_unlock ( &node->lock );
	
	return ret;
}

static telem * get_free_node (void) {

    telem * node;
	
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
	int i;
	
	major = register_chrdev(0, "dmatest", &fops);
	if ( major < 0 ) {
		
		pr_err("Char device registration failed.\n");
		goto err_gen;
		
	} else
		pr_info("Char device %d registered.\n", major);
	
    if (!register_debugfs()) {
		
		pr_err("Debugfs registration failed.\n");
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
			INIT_LIST_HEAD(&node->data);
			node->subt = -1;
			
			list_add_tail(&node->elem, &test_list);
			
		} else {
			
			pr_err("Error allocating element %d.\n", i);
			break;
			
		}
	}
	
	if (i == 0) {
		
		pr_err("No channels availbale.\n");
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
			dma_release_channel ( node->chan );
			
			mutex_unlock(&node->lock);
		}
	}
	
	unregister_chrdev ( major, "dmatest" );
	debugfs_remove_recursive ( root );
	
	return;
}

module_init(dmatest_init);
module_exit(dmatest_exit);
