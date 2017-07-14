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
static void print_parameters ( void );

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

LIST_HEAD(node_list);

static unsigned int major;

struct dma_attrs dma_attr;
static unsigned long long max_size = UINT_MAX;
char hr_size [32] = "4K";

/* Default value for parameters */

unsigned int dvc_value = 100;
unsigned long long glob_size = 4 * 1024;
unsigned int verbose = 0;
unsigned int periods = 1; /* For DMA_CYCLIC */

bool async_mode = true;
bool mode_2d = false;
bool direction = true;
static bool batch_mode = false;

struct dentry *root;

static bool register_debugfs (void) {

	struct dentry *d;
	
	root = debugfs_create_dir("dmatest", NULL);	
	if (!root || IS_ERR(root))
		goto err_reg;

	d = debugfs_create_u32("major", S_IRUGO, root, (u32 *)&major);
	if (IS_ERR_OR_NULL(d))
	    goto err_reg;

	d = debugfs_create_u32("max_chann", S_IRUGO, root, (u32 *)&max_chann);
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

	d = debugfs_create_u32("periods", S_IRUGO | S_IWUSR, root, (u32 *)&periods);
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
	
	d = debugfs_create_bool("direction", S_IRUGO | S_IWUSR, root, (u32 *)&direction);
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
		
		pr_warn("Size %s (%llu Bytes) is greater than the maximum allowed (~4G, %u Bytes), setting up PAGE_SIZE (4K, %lu Bytes).\n", hr_size, glob_size, UINT_MAX, PAGE_SIZE);

		memset(hr_size, 0, sizeof(hr_size));
		
		hr_size[0] = '4';
		hr_size[1] = 'K';
		
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

static void print_parameters (void) {
	
	pr_info("DVC_VALUE: %u\n", dvc_value);
	pr_info("MOVE_SIZE: %s (%llu Bytes)\n", hr_size, glob_size);
	pr_info("ASYNC_MODE: %s\n", async_mode ? "true" : "false");
	pr_info("2D_MODE: %s\n", mode_2d ? "true" : "false");
	pr_info("BATCH_MODE: %s\n", batch_mode ? "true" : "false");
	pr_info("DIRECTION: %s\n", direction ? "true" : "false");
	pr_info("PERIODS: %u\n", periods);
	pr_info("VERBOSE: %u\n\n", verbose);
	
}

static uint jobs_for_cmd (command * cmd) {

	uint ret;
	
	switch (cmd->cmd) 
		{
			
		case DMA_SLAVE_SG:
			{
				switch(cmd->args) {
				case 0:
				case 1:
				case 2:
					ret = 1;
				default:
					ret = 3;
				}
			}
			break;;
			   	
		case DMA_CYCL:
			{
				switch(cmd->args) {
				case 0:
				case 1:
				case 2:
				case 3:
					ret = 1;
				default:
					ret = 4;
				}
			}
			break;;
			
		case DMA_ILEAVED:
			{
				switch(cmd->args) {
				case 0:
				case 1:
				case 2:
				case 3:
					ret = 1;
				default:
					ret = 4;
				}
					
			}
			break;;
			
		case DMA_SCAT_GATH:
		case DMA_IRQ:			
		case DMA_MCPY:		
		case DMA_MSET:
			{ 
				ret = 1;
			}
			break;;
				
		case ALL_TESTS:
			{
				ret = 15;	
			}
			break;;
			
		default: 
			ret = 0;
		};

	return ret;
}

static void free_nodes (telem * nodes []) {

	uint i;
	telem * node;
	command * cmd, * temp;
	
	for (i = 0; i < max_chann; i++) {

		node = nodes[i];
		
		if (node) {
			
			list_for_each_entry_safe (cmd, temp, &node->cmd_list, elem) {

				node->pending -= jobs_for_cmd(cmd);
			    list_del(&cmd->elem);
				kfree(cmd);
			}
		}
	}
}

static ssize_t dev_receive ( struct file * file, const char *buff, size_t len, loff_t * off ) {
	
    unsigned int res;
	char * outter, * token, * test = "", * str = "";
	uint i = 0;
	telem * node;
	int args = -1, node_id = -1, com = -1; 
    command * cmd;
    telem * nodes [max_chann];

	*off += len;
	
	for (i = 0; i < max_chann; i++)
		nodes[i] = NULL;

	if (verbose >= 1)
		print_parameters();
	
	strcpy(str, buff);

	i = 0;
	
	while ((outter = strsep(&str, " "))) {
		
		test = "";
		strcpy(test, outter);
		
		while ((token = strsep(&test, ","))) {
			
			if (strcmp(token, "")) {
				
				if (!kstrtou32(token, 10, &res)) {
					
					switch (i) {
						
					case 0:
					    com = res;
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

		    cmd = (command *) kzalloc (sizeof(cmd), GFP_KERNEL);

			if (!cmd) {
				
				pr_err("Failed to allocate command, aborting.\n");
				free_nodes (nodes);
				return len;
				
			}

			cmd->cmd = com;
			cmd->args = args;
				
			if (node_id < 0)
				node = get_min_node(); /* Must allways return a node. */
			else
				node = get_node_by_id(node_id);
			
			if (node) {
				
				list_add_tail(&cmd->elem, &node->cmd_list);
				node->pending += jobs_for_cmd(cmd);
				nodes[node->id] = node;
				
			} else 	
			    pr_err("Node %d not existent.\n", node_id);
		}
		
	    com = args = node_id = -1;
	}
	
    for (i = 0; i < max_chann; i++) {
		
		if (nodes[i]) 	
			kthread_run ( run_test, nodes[i], "dmatest-worker" );
		
	}
	
	
	return len;
}

static bool cyclic_mem_to_mem_validate ( tjob * tinfo ) {

	uint i, j;
	bool passed = true;
	uint asize = tinfo->real_size / sizeof(unsigned long long);
	uint inner_asize = tinfo->amount / sizeof(unsigned long long);
	tdata * block = list_first_entry(&tinfo->data, tdata, elem);
	
	for ( j = 0, i = 0; passed && i < asize; i++ ) {
		passed = (block->input[i] == block->output[j]);
		j = ((j + 1) % inner_asize);
	}
   	
	return passed;

}

static bool memset_validation ( tjob * tinfo ) {

	uint i;
	bool passed = true;
	uint asize = tinfo->isize / sizeof(int);
	tdata * block = list_first_entry(&tinfo->data, tdata, elem);
   		
	for (i = 0; i < asize && passed; i++)
		passed = (block->input[i] == tinfo->memset_val);
   
	return passed;
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
				passed = (block->input[i] == *dvc);
			
			if (!passed)
				break;
		}
		
	} else {
		
		/* Very weak data integrity test, best we can do however ... */
		if (tinfo->tnum != DMA_CYCL) {

			dvc = block->input; 
			passed = list_entry(tinfo->data.prev, tdata, elem)->output[(tinfo->osize / sizeof(unsigned long long)) - 1] == *dvc;

		} else {

			/* We don't know in which cycle we stoped the transaction, so we check all the values for the last position of the period. */
			dvc = block->input;
		    passed = false;
			asize = tinfo->amount / sizeof(unsigned long long);
			block = list_entry(tinfo->data.prev, tdata, elem);
			
			for (i = (asize - 1); i < (tinfo->real_size / sizeof(unsigned long long)); i+= asize) {
				passed = (block->output[i] == *dvc);

				if (passed)
					break;
			}
		} 
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

	} else {
		
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

static bool sg_compare ( tjob * tinfo ) {

	tdata * min_block, * max_block, * block_src = list_first_entry(&tinfo->data, tdata, elem);
	tdata * block_dst = block_src;
	unsigned int max_size, min_size, i = 0, j = 0;
	unsigned long long * max_array, * min_array;
	bool passed = true;
	
    while (!block_dst->dst_dma)
		block_dst = list_next_entry(block_dst, elem);
		
    if (tinfo->isize > tinfo->osize) {

		min_block = block_src;
		max_block = block_dst;
		
		max_size = tinfo->isize / sizeof(unsigned long long);
		min_size = tinfo->osize / sizeof(unsigned long long);

		min_array = min_block->output;
		max_array = max_block->input;
		
	} else {
		
		min_block = block_dst;
		max_block = block_src;
		
		max_size = tinfo->osize / sizeof(unsigned long long);
		min_size = tinfo->isize / sizeof(unsigned long long);

		min_array = min_block->input;
		max_array = max_block->output;
	}

	while ((max_block || min_block) && passed) {
		
		while (i < max_size && j < min_size && passed) {
			passed = (min_array[j] == max_array[i]);
			i ++;
			j ++;
		}

		if (passed) {

			if (i == max_size) {

				max_block = !list_is_last(&max_block->elem, &tinfo->data) ? list_next_entry(max_block, elem) : NULL;

				if (tinfo->isize > tinfo->osize)
					max_array = max_block->input;
				else
					max_array = max_block->output;
				
				i = 0;
					
			}
			
			if (j == min_size) {
				
				min_block = !list_is_last(&min_block->elem, &tinfo->data) ? list_next_entry(min_block, elem) : NULL;

				if (tinfo->isize < tinfo->osize)
					min_array = max_block->input;
				else
					min_array = max_block->output;
				
				j = 0;
				
			}
		}
	}

	return passed;
}

bool check_results ( tjob * tinfo ) {
	
	switch ( tinfo->tnum ) {
	case DMA_SLAVE_SG:
		if (tinfo->subt <= 2)
			return dvc_vs_array(tinfo);
		else
			return dvc_vs_dvc(tinfo);
	case DMA_CYCL:
		if (tinfo->subt == 0) 
			return cyclic_mem_to_mem_validate(tinfo);
	case DMA_ILEAVED:
		switch(tinfo->subt) {
		case 0:
			return array_vs_array(tinfo);
		case 1:
		case 2:
			return dvc_vs_array(tinfo);
		case 3:
			return dvc_vs_dvc(tinfo);
		}
	case DMA_SCAT_GATH:
		return sg_compare(tinfo);
	case DMA_IRQ:
		return true;
	case DMA_MCPY:
		return array_vs_array(tinfo);
	case DMA_MSET:
		return memset_validation(tinfo);
	default:
		pr_warn("%u >> %s: Unknown test %u\n", tinfo->parent->id, __func__, tinfo->tnum);
		return false;
	}	
}

static void print_block (tjob * job, tdata * block, int idx) {

    long long inpt, oupt;
	uint i;
    unsigned int elem_size = (job->tnum == DMA_MSET) ? sizeof (int) : sizeof(unsigned long long);
	
	if (idx >= 0)
		pr_info("%u >> Block %u [%p - 0x%08x] [%p - 0x%08x]: \n", job->parent->id, idx, block->input, block->dst_dma, block->output, block->src_dma);
	
	for (i = 0; i < ((unsigned long)job->real_size / elem_size); i++) {

		oupt = job->tnum == DMA_MSET ? job->memset_val : *block->output;
		inpt = *block->input;
		
		switch (job->subt) {
		case 0:
			oupt = block->output[i];
			inpt = block->input[i];
		case 1:
			inpt = block->input[i];
			break;
		case 2:
			oupt = block->output[i];
			break;
		default:
			break;
		}
		
		pr_info("%u >> %03d: %03llu - %03llu\n", job->parent->id, i, oupt, inpt);
	}
}

static bool terminate_node ( int node_id ) {

	telem * node = get_node_by_id ( node_id );	
	enum dma_status ret = DMA_SUCCESS;
	tjob * job, * temp;
	tdata * block, * tmp;
	bool check = true;
	
	if ( node ) {

		if (node->chan)
			ret = dmaengine_terminate_all ( node->chan );
			
		list_for_each_entry_safe (job, temp, &node->jobs, elem) {
			
			if (job->tnum == DMA_CYCL) {

				check = check_results(job);

				if (!check)
					pr_err("%u >> Data integriry check failed for test %u (%s).\n", job->parent->id, job->tnum, job->tname);
				else
					pr_warn("%u >> Data integriry check success for test %u (%s).\n", job->parent->id, job->tnum, job->tname);
				
			}
			
			list_for_each_entry_safe (block, tmp, &job->data, elem) {

				if (job->tnum == DMA_CYCL && verbose >= 3) 	
					print_block(job, block, -1);
				
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
		
		spin_lock (&node->lock);
		node->pending = 0;
		spin_unlock (&node->lock);

		if (node->chan)
			pr_info("%u >> Node %d (%s) terminated\n", node_id, node->id, dma_chan_name(node->chan));

		if (node->chan)
			dma_release_channel ( node->chan );
		
		node->chan = NULL;
		
	} else
		pr_err("Node %d not existent.\n", node_id);
	
	return ret == DMA_SUCCESS;
}

/* Perform queued jobs on a given node */
static bool perform_jobs ( int node_id ) {

	telem * node = get_node_by_id ( node_id );
	tjob * job;
	bool ret = true;

	if (node) {

		/* 
		   Only the first call to "dma_async_issue_pending" will have effect here, 
		   done this way to finish transactions not configured as asyncronous in the
		   moment of its submission.
		   
		*/
		
		list_for_each_entry (job, &node->jobs, elem) 
			ret = ret && issue_transaction ( job ); 

	} else
		pr_err("Node %d not existent.\n", node_id);
	
	return ret;
}

/* Pause dma channel on a given node */
static bool pause_chan ( int node_id ) {

	telem * node = get_node_by_id ( node_id );
	enum dma_status ret = DMA_ERROR;

	if (node) {
		
	    if (node->chan)
			ret = dmaengine_pause (node->chan);
		else
			pr_warn("%d >> Node %d does not have a channel reserved.\n", node_id, node_id);
	} else
		pr_err("Node %d not existent.\n", node_id);
	
	return ret == DMA_PAUSED;
}

/* Resume dma channel on a given node */
static bool resume_chan ( int node_id ) {

	telem * node = get_node_by_id ( node_id );
	enum dma_status ret = DMA_ERROR;

	if (node) {
		
		if (node->chan)
			ret = dmaengine_resume (node->chan); 
		else
			pr_warn("%d >> Node %d does not have a channel reserved.\n", node_id, node_id);
	} else
		pr_err("Node %d not existent.\n", node_id);
	
	return ret == DMA_SUCCESS || ret == DMA_IN_PROGRESS;
}

static bool issue_transaction ( tjob * tinfo ) {

	tinfo->stime = jiffies;
	dma_async_issue_pending(tinfo->parent->chan);

	pr_info("%u >> Issued transaction (%d)\n", tinfo->parent->id, tinfo->tx_cookie);
	
	if (!tinfo->async) 	
		return finish_transaction ( tinfo );
	
	return true;
}

bool submit_transaction ( tjob * tinfo ) {

	if(!tinfo->tx_desc) {
		
		pr_err("%u >> Unable to get descriptor\n", tinfo->parent->id);
		return false;
		
	} else
		pr_info("%u >> Got descriptor (%pB)\n", tinfo->parent->id, tinfo->tx_desc);

	if (tinfo->tnum == DMA_CYCL) {

		tinfo->tx_desc->callback = (verbose >= 4) ? (void *) &cyclic_callback : NULL;
		tinfo->tx_desc->callback_param = (verbose >= 4) ? (void *) tinfo : NULL;
			
	} else {

		tinfo->tx_desc->callback = async_mode ? (void *) &finish_transaction : NULL;
		tinfo->tx_desc->callback_param = async_mode ? (void *) tinfo : NULL;

	}
	
	tinfo->tx_cookie = dmaengine_submit(tinfo->tx_desc);
	
	if(tinfo->tx_cookie < 0) 
		pr_err("%u >> Error submitting transaction (%d)\n", tinfo->parent->id, tinfo->tx_cookie);
	else
		pr_info("%u >> Cookie submitted (%d)\n", tinfo->parent->id, tinfo->tx_cookie);

	tinfo->async = async_mode;
	
	if (!batch_mode)
		return issue_transaction ( tinfo );
    
	return true;
}

static bool finish_transaction ( void * args ) {
	
    tjob * tinfo = (tjob *) args;
	tdata * block, * temp;
	enum dma_status to = DMA_SUCCESS;
	uint j = 0;
	bool check = false;
	unsigned long diff = jiffies - tinfo->stime;

	if (!tinfo->async)
		to = dma_wait_for_async_tx(tinfo->tx_desc);

    if (to != DMA_ERROR)
		check = check_results(tinfo);
		
	if (!check)
		pr_err("%u >> Data integriry check failed for test %u (%s).\n", tinfo->parent->id, tinfo->tnum, tinfo->tname);
	else
		pr_warn("%u >> Data integriry check success for test %u (%s).\n", tinfo->parent->id, tinfo->tnum, tinfo->tname);
	
	list_for_each_entry_safe (block, temp, &tinfo->data, elem) {
		
		if (to != DMA_ERROR) {
			
			if (block->dst_dma && verbose >= 3)	
				print_block(tinfo, block, j);
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
		pr_info("%u >> Moved %s (%llu Bytes) in %u nanoseconds.\n", tinfo->parent->id, hr_size, tinfo->real_size ? tinfo->real_size : glob_size, jiffies_to_usecs(diff));

	spin_lock(&tinfo->parent->lock);
	
	if (! --tinfo->parent->pending) {

		pr_info("%u >> Releasing dma channel %s.\n", tinfo->parent->id, dma_chan_name(tinfo->parent->chan));
		dma_release_channel ( tinfo->parent->chan );
		tinfo->parent->chan = NULL;
	}
	
	list_del(&tinfo->elem);
	spin_unlock(&tinfo->parent->lock);
	
	kfree(tinfo); 
	   
    return (to != DMA_ERROR) && check;
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
    pr_err("%u >> Error mapping DMA addresses.", tinfo->parent->id);
	
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
		
		pr_err("%u >> Error allocating new job.\n", node->id);
		return NULL;
		
	} 
	
	INIT_LIST_HEAD(&job->data);
	
	job->parent = node;
	job->tnum = test;
	job->subt = subtest;

	spin_lock(&node->lock);
	
	list_add_tail(&job->elem, &node->jobs);
	
	spin_unlock(&node->lock);
	
	return job;
}

static int run_test (void * node_ptr) {
	
	telem * node = (telem *) node_ptr;
    command * cmd, * temp;
	int ret = true;

	list_for_each_entry_safe (cmd, temp, &node->cmd_list, elem) {

		pr_info("%u >> Running command %u (args: %d).\n", node->id, cmd->cmd, cmd->args);
		
		if (cmd->cmd <= ALL_TESTS) {
		
			if (!node->chan) {
				
				node->chan = dma_request_channel ( mask, NULL, NULL );
				
				if (!node->chan) {
					
					pr_err("%u >> No dma channel available.\n", node->id);
					return 0;
					

				} else
					pr_info("%u >> Reserved channel %s.\n", node->id, dma_chan_name(node->chan));

			} else
				pr_info("%u >> Performing transaction on channel %s.\n", node->id, dma_chan_name(node->chan));

		} 
		
		switch (cmd->cmd) 
			{
			
			case DMA_SLAVE_SG:
				{
					switch(cmd->args) {
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
				
			case DMA_CYCL:
				{
					switch(cmd->args) {
					case 0:
						ret = do_cyclic_mem_to_mem ( node );
						break;;
					case 1:
						ret = do_cyclic_dev_to_mem ( node );
						break;;
					case 2:
						ret = do_cyclic_mem_to_dev ( node );
						break;;
					case 3:
						ret = do_cyclic_dev_to_dev ( node );
						break;;
					default:
						ret = do_dma_cyclic ( node );
					}
				}
				break;;

			case DMA_ILEAVED:
				{
					switch(cmd->args) {
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
						ret = do_dma_ileaved ( node );
					}
					
				}
				break;;
				
			case DMA_SCAT_GATH:
				{ 
					ret = do_dma_scatter_gather ( node );
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
				

				/* Extra cmds */
			

			case ISSUE_JOBS:
				{
					int i;
				
					if (cmd->args < 0) {
						for (i = 0; i < max_chann; i++)
							ret = ret && perform_jobs ( i );
					} else
						ret = perform_jobs ( cmd->args );
				}
				break;;
			
			case TERMINATE_NODE:
				{
					int i;
				
					if (cmd->args < 0) {
						for (i = 0; i < max_chann; i++)
							ret = ret && terminate_node ( i );
					} else
						ret = terminate_node ( cmd->args );
				
				}
				break;;
				
			case PAUSE_CHAN:
				{
					int i;
				
					if (cmd->args < 0) {
						for (i = 0; i < max_chann; i++)
							ret = ret && pause_chan ( i );
					} else
						ret = pause_chan ( cmd->args );
				
				}
				break;;

			case RESUME_CHAN:
				{
					int i;
				
					if (cmd->args < 0) {
						for (i = 0; i < max_chann; i++)
							ret = ret && resume_chan ( i );
					} else
						ret = resume_chan ( cmd->args );
				
				}
				break;;
			
			default: 
			
				pr_err("%u >> Invalid command requested: %u.\n", node->id, cmd->cmd);
				ret = false;
			
			};
	
		if (!ret)
			pr_err("%u >> Error running command (%u).\n", node->id, cmd->cmd);
		
		list_del(&cmd->elem);
		kfree(cmd);
	}
	
	return 1;
}

static telem * get_node_by_id ( uint id ) {

    telem * node;
	
	list_for_each_entry(node, &node_list, elem) {
		
		if (node->id == id)  
			return node;
	}
	
	return NULL;
}

/* Get the node with minimum load. */
static telem * get_min_node (void) {

    telem * node, * ret = NULL;
	uint minim = UINT_MAX;
	
	list_for_each_entry(node, &node_list, elem) {
		
		if (node->pending == 0) {
			
			return node;
			
		} else if (node->pending < minim) {

			minim = node->pending;
			ret = node;
		}
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
	
	for (i = 0; i < max_chann; i++) {
		
		telem * node = (telem *) kzalloc(sizeof(telem), GFP_KERNEL);
		
		if (node) {

			node->id = i;
			
			spin_lock_init(&node->lock);
			INIT_LIST_HEAD(&node->jobs);
			INIT_LIST_HEAD(&node->cmd_list);
			node->pending = 0;

			list_add_tail(&node->elem, &node_list);
			
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
	
	list_for_each_entry_safe(node, temp, &node_list, elem) {
		
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
