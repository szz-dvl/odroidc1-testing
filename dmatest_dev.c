//#include <linux/moduleparam.h>
#include "dmatest.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("S805 Dmaengine tester");
MODULE_AUTHOR("szz");

static unsigned int max_chann = 4;
module_param(max_chann, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(max_chann, "Maximum number of dma channels available.");

static ssize_t dev_receive ( struct file * file, const char *buff, size_t len, loff_t * off );
static ssize_t size_receive ( struct file * file, const char *buff, size_t len, loff_t * off );
static ssize_t size_send ( struct file * file,  char *buff, size_t len, loff_t * off );
static int size_open (struct inode * inode, struct file * filep);
static telem * get_min_node ( void );
static bool register_debugfs ( void );
static int run_test ( void * node_ptr );
static bool finish_transaction ( void * tinfo );
static bool array_vs_array ( tjob * tinfo );
static bool dvc_vs_array ( tjob * tinfo );
static bool dvc_vs_dvc ( tjob * tinfo );
static bool issue_transaction ( tjob * tinfo );
static bool terminate_node ( int node_id );
static bool perform_jobs ( int node_id );
static telem * get_node_by_id ( uint id );

static struct file_operations fops = {
	.write = dev_receive
};

static struct file_operations size_fops = {
	.write = size_receive,
	.read = size_send,
	.open = size_open
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
LIST_HEAD(jobs_list);

static unsigned int major;

struct dma_attrs dma_attr;
static unsigned long long max_size = UINT_MAX;

/* Default value for parameters */

unsigned int dvc_value = 100;
unsigned int verbose = 1;
unsigned long long glob_size = 4 * 1024;

bool async_mode = true;
bool mode_2d = false;
static bool batch_mode = false;

char hr_size [32] = "4K";

struct dentry *root;

static bool register_debugfs (void) {

	struct dentry *d;
	
	root = debugfs_create_dir("dmatest", NULL);	
	if (!root || IS_ERR(root))
		goto err_reg;
	
	d = debugfs_create_u32("major", S_IRUGO, root, (u32 *)&major);
	if (IS_ERR_OR_NULL(d))
	    goto err_reg;
	
	d = debugfs_create_file("glob_size", S_IRUGO | S_IWUSR, root, hr_size, &size_fops);
	if (IS_ERR_OR_NULL(d))
	    goto err_reg;
	
	d = debugfs_create_u32("dvc_value", S_IRUGO | S_IWUSR, root, (u32 *)&dvc_value);
	if (IS_ERR_OR_NULL(d))
	    goto err_reg;
	
	d = debugfs_create_u32("verbose", S_IRUGO | S_IWUSR, root, (u32 *)&verbose);
	if (IS_ERR_OR_NULL(d))
	    goto err_reg;
	
	d = debugfs_create_bool("async_mode", S_IRUGO | S_IWUSR, root, (u32 *)&async_mode);
	if (IS_ERR_OR_NULL(d))
	    goto err_reg;

	d = debugfs_create_bool("2d_mode", S_IRUGO | S_IWUSR, root, (u32 *)&mode_2d);
	if (IS_ERR_OR_NULL(d))
	    goto err_reg;

	d = debugfs_create_bool("batch_mode", S_IRUGO | S_IWUSR, root, (u32 *)&batch_mode);
	if (IS_ERR_OR_NULL(d))
	    goto err_reg;
	
	return true;
	
 err_reg:
	debugfs_remove_recursive(root);
	return false;
}

static ssize_t size_receive ( struct file * file, const char *buff, size_t len, loff_t * off ) {

	char * my_size = hr_size;
	
    memset(my_size, 0, sizeof(hr_size));
	
	if (*off >= 32) 
		return 0;
	
	if (*off + len > 32)
		len = 32 - *off;
	
	if (copy_from_user(hr_size + *off, buff, len))
		return -EFAULT;
	
	glob_size = memparse(my_size, &my_size);

	if (glob_size > max_size) {

		pr_info("Size %s (%llu Bytes) is greater than the maximum allowed (~4G, %u Bytes), setting up PAGE_SIZE (4K, %lu Bytes).\n", my_size, glob_size, UINT_MAX, PAGE_SIZE);
		
		memset(my_size, 0, sizeof(hr_size));
		strcpy(my_size, "4K");
		glob_size = PAGE_SIZE;
	}
	
	*off += len;
	
	return len;
}

static ssize_t size_send ( struct file * file, char __user *buff, size_t len, loff_t * off ) {

	if (*off >= 32)
		return 0;
	
	if (*off + len > 32)
		len = 32 - *off;
	
	if (copy_to_user(buff, hr_size + *off, sizeof(hr_size)))
		return -EFAULT;
	
	*off += len;
	
	return len;
}

static int size_open (struct inode * inode, struct file * filep) {

	filep->private_data = inode->i_private;
	
	return 0;
}

static ssize_t dev_receive ( struct file * file, const char *buff, size_t len, loff_t * off ) {
	
    unsigned int res;
	char * outter, * token, * test = "", * str = "";
	uint i = 0;
	telem * node;
	int args = -1, node_id = -1, cmd = -1;
	
	strcpy(str, buff);
	
	while ((outter = strsep(&str, " "))) {
		
		test = "";
		strcpy(test, outter);
			
		while ((token = strsep(&test, ","))) {
			
			if (strcmp(token, "")) {
				
				if (!kstrtou32(token, 10, &res)) {
					
					switch (i) {
						
					case 0:
						cmd = res;
						break;;
					case 1:
						args = (int) res;
						break;;
					case 2:
						node_id = (int) res;
						break;;
					default:
						break;;	
					}
					
					i++;
					
				} else
					pr_err("Invalid test receieved: %s\n", token);
			}	
		}

		i = 0;

		if (cmd >= 0) {
			
			if (node_id < 0)
				node = get_min_node(); /* Must allways return a node. */
			else
				node = get_node_by_id(node_id);

			if (node) {

			    node->selectable = false;
				node->cmd = cmd;
				node->args = args;
				
				pr_info("Running cmd %u (args: %d) on node %u\n", node->cmd, node->args, node->id);
				
				kthread_run ( run_test,
							  node,
							  "dmatest-worker" );	
			} else 	
			    pr_err("Node %d not existent or temporaly busy.\n", node_id);
		}
		
		cmd = args = node_id = -1;
	}
	
	return len;
}

static bool dvc_vs_array ( tjob * tinfo ) {

	unsigned long long * dvc;
	uint asize, i;
	tdata * block;
	bool passed = true;

	block = list_first_entry(&tinfo->data, tdata, elem);

	/* Like memset actually */
	if (tinfo->isize > tinfo->osize) {
		
		dvc = block->output;
		asize = tinfo->isize / sizeof(unsigned long long);
		
		list_for_each_entry(block, &tinfo->data, elem) {
			
			for (i = 0; i < asize && passed; i++)
				passed = block->input[i] == *dvc;
			
			if (!passed)
				break;
		}
		
	} else {
		
		/* Very weak data integrity test, best we can do however ... */
		
		dvc = block->input; 
		passed = list_entry(tinfo->data.prev, tdata, elem)->output[(tinfo->osize / sizeof(unsigned long long)) - 1] == *dvc;
		
	}
	
	return passed;
}

static bool array_vs_array ( tjob * tinfo ) {

	unsigned long long * data_container;
	tdata * block;
	bool passed = true;
	uint i, asize, j = 0;
	
	block = list_first_entry(&tinfo->data, tdata, elem);
	
	/* Array merge vs array split. */
	if (tinfo->isize > tinfo->osize) {
		
		data_container = block->input;
		asize = tinfo->osize / sizeof(unsigned long long);

	} else { /* yet unimplemented */
		
		data_container = block->output;
		asize = tinfo->isize / sizeof(unsigned long long);
	}
	
	list_for_each_entry(block, &tinfo->data, elem) {
		
		for (i = 0; i < asize && passed; i++)
			passed = (tinfo->isize > tinfo->osize) ? block->output[i] == data_container[j++] : block->input[i] == data_container[j++];
		
		if (!passed)
		    break;
	}
	
	return passed;
}

static bool dvc_vs_dvc ( tjob * tinfo ) {

	tdata * block = list_first_entry(&tinfo->data, tdata, elem);
   
	return *block->input == *block->output;
	
}

static bool check_results ( tjob * tinfo ) {
	
	switch ( tinfo->tnum ) {
	case 0:
		if (tinfo->subt <= 1)
			return dvc_vs_array(tinfo);
		else
			return dvc_vs_dvc(tinfo);
	case 3:
		return array_vs_array(tinfo);		
	default:
		pr_info("Check results not implemented for test %u\n", tinfo->tnum);
		return true;
	}	
}

static bool terminate_node ( int node_id ) {

	telem * node = get_node_by_id ( node_id );	
	enum dma_status ret = DMA_SUCCESS;
	tjob * job, * temp;
	tdata * block, * tmp;
	
	if ( node && node->pending ) {
		
		ret = dmaengine_terminate_all ( node->chan );
		
		list_for_each_entry_safe (job, temp, &node->jobs, elem) {

			list_for_each_entry_safe (block, tmp, &job->data, elem) {
				
				if (block->dst_dma)
					dma_free_coherent(node->chan->device->dev, job->isize, block->input, block->dst_dma);
				
				if (block->src_dma)
					dma_free_coherent(node->chan->device->dev, job->osize, block->output, block->src_dma);
		
				list_del(&block->elem);
				kfree(block);
		
			}

			list_del(&job->elem);
			kfree(job);
		}
		
		node->pending = 0;
		dma_release_channel ( node->chan );
		node->chan = NULL;

	} else
		pr_err("Node %d not existent or temporaly busy.\n", node_id);
	
	return ret == DMA_SUCCESS; /* Must always be true */
}

/* Perform queued jobs on a given node */
static bool perform_jobs ( int node_id ) {

	telem * node = get_node_by_id ( node_id );
	tjob * job;
	bool ret = true;

	if (node) {
		
		list_for_each_entry (job, &node->jobs, elem) 
			ret = ret && issue_transaction ( job );

	} else
		pr_err("Node %d not existent or temporaly busy.\n", node_id);
	
	return ret;
}

static bool issue_transaction ( tjob * tinfo ) {

	tinfo->stime = jiffies;
	dma_async_issue_pending(tinfo->parent->chan);
	
	if (!tinfo->async) 	
		return finish_transaction ( tinfo );
	
	return true;
}

bool submit_transaction ( tjob * tinfo ) {

	if(!tinfo->tx_desc) {
		
		pr_err("Unable to get descriptor\n");
		return false;
		
	} else
		pr_info("Got descriptor: %pB\n", tinfo->tx_desc);
	
    tinfo->tx_desc->callback = async_mode ? (void *) &finish_transaction : NULL;
	tinfo->tx_desc->callback_param = async_mode ? (void *) tinfo : NULL;
	
	tinfo->tx_cookie = dmaengine_submit(tinfo->tx_desc);
	
	if(tinfo->tx_cookie < 0) 
		pr_err("Error submitting transaction: %d\n", tinfo->tx_cookie);
	else
		pr_info("Cookie submitted: %d\n", tinfo->tx_cookie);

	tinfo->async = async_mode;
	
	if (!batch_mode) {

		spin_lock (&tinfo->parent->lock);
		
		if (! --tinfo->parent->batch_size) {
			spin_unlock (&tinfo->parent->lock);
			return issue_transaction ( tinfo );
			
		} else
			spin_unlock (&tinfo->parent->lock);
	}
	
	return true;
}

static bool finish_transaction ( void * args ) {
	
    tjob * tinfo = (tjob *) args;
	tdata * block, * temp;
	enum dma_status to = DMA_SUCCESS;
	uint i, j = 0;
	bool check = false;

	if (!tinfo->async)
		to = dma_wait_for_async_tx(tinfo->tx_desc);

    if (to != DMA_ERROR)
		check = check_results(tinfo);
		
	if (!check)
		pr_err("Data integriry check failed for test %s.\n", tinfo->tname);
	else
		pr_info("Data integriry check success for test %s.\n", tinfo->tname);
	
	list_for_each_entry_safe (block, temp, &tinfo->data, elem) {
		
		if (to != DMA_ERROR) {
			
			if (block->dst_dma && verbose >= 3) {
				
				pr_info("Block %u [%p][0x%08x]: \n", j, block->input, block->dst_dma);
				
				for (i = 0; i < (tinfo->isize / sizeof(unsigned long long)); i++)
					pr_info("%03d: %03llu, 0x%08llx\n", i, block->input[i], block->input[i]);
				
			}
		}
		
		if (block->dst_dma)
			dma_free_coherent(tinfo->parent->chan->device->dev, tinfo->isize, block->input, block->dst_dma);
		
		if (block->src_dma)
			dma_free_coherent(tinfo->parent->chan->device->dev, tinfo->osize, block->output, block->src_dma);
		
		list_del(&block->elem);
		kfree(block);
		
		j ++;
	}
	
	if (to != DMA_ERROR && check)
		pr_info("Moved %s (%llu Bytes) in %u nanoseconds.\n", hr_size, glob_size, jiffies_to_usecs(jiffies - tinfo->stime));

	spin_lock(&tinfo->parent->lock);
	
	if (! --tinfo->parent->pending) {
		
		dma_release_channel ( tinfo->parent->chan );
		tinfo->parent->chan = NULL;
		
	}
	
	list_del(&tinfo->elem);
	spin_unlock(&tinfo->parent->lock);
	
	kfree(tinfo); 
	   
    return to != DMA_ERROR && check;
}

bool allocate_arrays (tjob * tinfo, uint amount, uint isize, uint osize) {

	/* Either @osize or @isize must evaluate to true here (> 0). */
	
	uint i;
	tdata * block, * temp;
	
	for (i = 0; i < amount; i++) {
		
	    block = (tdata *) kzalloc(sizeof(tdata), GFP_KERNEL);	

		if (isize) {
			
			block->input = dma_alloc_coherent(tinfo->parent->chan->device->dev,
											  isize,
											  &block->dst_dma,
											  async_mode ? GFP_ATOMIC : GFP_KERNEL); /* Frees will fail if in_interrupt() and allocated as GFP_KERNEL, more info: arch/arm/mm/dma-mapping.c */
			
			if (dma_mapping_error(tinfo->parent->chan->device->dev, block->dst_dma)) 
				goto map_error;
			else
				memset(block->input, 0, isize);
		}
		
		if (osize) {
			
			block->output = dma_alloc_coherent(tinfo->parent->chan->device->dev,
											   osize,
											   &block->src_dma,
											   async_mode ? GFP_ATOMIC : GFP_KERNEL);
			
			if (dma_mapping_error(tinfo->parent->chan->device->dev, block->src_dma)) 
				goto map_error;
		} 
		
		list_add_tail(&block->elem, &tinfo->data);
	}
	
	return true;
	
 map_error:
    pr_err("Error mapping DMA addresses.");
	
    list_for_each_entry_safe(block, temp, &tinfo->data, elem) {
		
		if (block->input)
		    dma_free_coherent(tinfo->parent->chan->device->dev, isize, block->input, block->dst_dma);
		
		if (block->output)
		    dma_free_coherent(tinfo->parent->chan->device->dev, osize, block->output, block->src_dma);
		
		list_del(&block->elem);
		kfree(block);
	}
	
	return false;
}

tjob * init_job (telem * node, uint test, int subtest) {
	
	tjob * job = (tjob *) kzalloc(sizeof(tjob), GFP_KERNEL);
	
	if (!job) {
		
		pr_err("Error allocating new job.\n");
		return NULL;
		
	} 
			
	INIT_LIST_HEAD(&job->data);
	
	job->parent = node;
	job->tnum = test;
	job->subt = subtest;

	spin_lock(&node->lock);
	
	list_add_tail(&job->elem, &node->jobs);
	
	node->batch_size += 1;
	node->pending += 1;

	node->selectable = true;
	spin_unlock(&node->lock);
	
	return job;
}

static int run_test (void * node_ptr) {
	
	telem * node = (telem *) node_ptr;
	int ret = true;
	
	pr_info("DVC_VALUE: %u\n", dvc_value);
	pr_info("MOVE_SIZE: %s (%llu Bytes)\n", hr_size, glob_size);
	pr_info("ASYNC_MODE: %s\n", async_mode ? "true" : "false");
	pr_info("2D_MODE: %s\n", mode_2d ? "true" : "false");
	pr_info("BATCH_MODE: %s\n", batch_mode ? "true" : "false");
	pr_info("VERBOSE: %u\n", verbose);

	if (node->cmd <= ALL_TESTS) {
		
		if (!node->chan) {
			
			node->chan = dma_request_channel ( mask, NULL, NULL );
			
			if (!node->chan) {
				
				pr_err("No channel available.\n");
				return 0;
				
			}
		}
		
	} else
		node->selectable = true;
	
	switch (node->cmd) 
		{
			
		case DMA_SLAVE_SG:
			{
				switch(node->args) {
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
				switch(node->args) {
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
				switch(node->args) {
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
				
		case ALL_TESTS:
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
				

			/* Extra commands */


		case ISSUE_JOBS:
			{
				int i;
				
				if (node->args < 0) {
					for (i = 0; i < max_chann + 2; i++)
						ret = ret && perform_jobs ( i );
				} else
					ret = perform_jobs ( node->args );
			}
			break;;
			
		case TERMINATE_NODE:
			{
				int i;
				
				if (node->args < 0) {
					for (i = 0; i < max_chann + 2; i++)
						ret = ret && terminate_node ( i );
				} else
					ret = terminate_node ( node->args );
				
			}
			break;;
			
		default: 
			
			pr_err("Invalid command requested: %u.\n", node->cmd);
			ret = false;
			
		};
	
	if (!ret)
		pr_err("Error running command %u.\n", node->cmd);
	
    node->args = -1;
	
	return ret;
}

static telem * get_node_by_id ( uint id ) {

    telem * node;
	
	list_for_each_entry(node, &test_list, elem) {

		if (!node->selectable)
			continue;
		
		if (node->id == id)  
			return node;
	}
	
	return NULL;
}

/* Get the node with minimum load. */
static telem * get_min_node (void) {

    telem * node, * ret = NULL;
	uint minim = UINT_MAX;
	
	list_for_each_entry(node, &test_list, elem) {

		spin_lock (&node->lock);

		if (!node->selectable)
			continue;
		
		if (node->pending == 0) {

			spin_unlock (&node->lock);
			return node;

		} else if (node->pending < minim) {
			
			ret = node;
			minim = node->pending;
			
		}
		
		spin_unlock (&node->lock);
	}

	return ret;
}

static int __init dmatest_init(void)
{
	int i;

	init_dma_attrs(&dma_attr);
	
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
	
	for (i = 0; i < (max_chann + 2); i++) {
		
		telem * node = (telem *) kzalloc(sizeof(telem), GFP_KERNEL);

		if (node) {

			node->id = i;
			
			spin_lock_init(&node->lock);
			INIT_LIST_HEAD(&node->jobs);
			node->pending = 0;
			node->batch_size = 0;
			node->args = -1;
			node->selectable = true;
			
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

	telem * node, * temp;
	
	list_for_each_entry_safe(node, temp, &test_list, elem) {
		
		if (node->pending) 
			terminate_node( node->id );
		
		list_del(&node->elem);
		kfree(node);
	}
	
	unregister_chrdev ( major, "dmatest" );
	debugfs_remove_recursive ( root );
	
	return;
}

module_init(dmatest_init);
module_exit(dmatest_exit);
