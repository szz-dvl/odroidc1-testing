#include "cryptotest.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("s805 Crypto test");
MODULE_AUTHOR("szz");

static unsigned int max_node = 4;
module_param(max_node, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(max_node, "Maximum number of nodes available.");

static bool register_debugfs (void);
static int par_open (struct inode * inode, struct file * filep);
static ssize_t dev_receive ( struct file * file, const char *buff, size_t len, loff_t * off );
static ssize_t text_receive ( struct file * file, const char *buff, size_t len, loff_t * off );
static ssize_t text_send ( struct file * file, char __user *buff, size_t len, loff_t * off );
static ssize_t key_receive ( struct file * file, const char *buff, size_t len, loff_t * off );
static ssize_t key_send ( struct file * file, char __user *buff, size_t len, loff_t * off );
static tjob * init_job (telem * node, command * cmd);
static tjob * get_job (telem * node, command * cmd);
static int run_test (void * node_ptr);
static void free_nodes (telem * nodes []);
static telem * get_min_node (void);
	
static struct file_operations fops = {
	.write = dev_receive,
	/* .read = dev_send */
};

static struct file_operations key_fops = {
	.write = key_receive,
	.read = key_send,
	.open = par_open
};

static struct file_operations text_fops = {
	.write = text_receive,
	.read = text_send,
	.open = par_open
};

LIST_HEAD(node_list);

static spinlock_t text_lock;
static spinlock_t key_lock;

static unsigned int major, job_id = 0;
struct dentry *root;

static unsigned int keylen, textlen;
static char key [KEY_SIZE_MAX];
static char * text;

uint verbose = 0;

bool valid_state ( tjob * job ) {
	
	switch (job->tnum) {
		
	case CRYPTO_AES:
		return (job->data->keylen >= AES_MIN_KEY_SIZE && job->data->keylen <= AES_MAX_KEY_SIZE) && (job->tmode < CRYPTO_TDES_CBC);
	case CRYPTO_TDES:
		return (job->data->keylen == KEY_SIZE_8B || job->data->keylen == KEY_SIZE_24B) && (job->tmode == CRYPTO_TDES_CBC && job->tmode == CRYPTO_TDES_ECB);
	case CRYPTO_CRC:
	case CRYPTO_DIVX:
		return true;
	default:
		return false;
	}
}

void destroy_job ( tjob * job ) {

	list_del(&job->elem);
	
	if (job->data->key)
		kfree(job->data->key);

	kfree(job->data->text);
	kfree(job->data->spec);
	kfree(job->data);
	kfree(job);
}

static bool register_debugfs (void) {

	struct dentry *d;
	
	root = debugfs_create_dir("cryptotest", NULL);	
	if (!root || IS_ERR(root))
		goto err_reg;

	d = debugfs_create_u32("max_nodes", S_IRUGO, root, (u32 *)&max_node);
	if (IS_ERR_OR_NULL(d))
	    goto err_reg;
	
	d = debugfs_create_u32("major", S_IRUGO, root, (u32 *)&major);
	if (IS_ERR_OR_NULL(d))
	    goto err_reg;

	d = debugfs_create_u32("job_id", S_IRUGO, root, (u32 *)&job_id);
	if (IS_ERR_OR_NULL(d))
	    goto err_reg;

	d = debugfs_create_u32("keylen", S_IRUGO, root, (u32 *)&keylen);
	if (IS_ERR_OR_NULL(d))
	    goto err_reg;

	d = debugfs_create_u32("verbose", S_IRUGO | S_IWUSR, root, (u32 *)&verbose);
	if (IS_ERR_OR_NULL(d))
	    goto err_reg;
	
	d = debugfs_create_file("key", S_IRUGO | S_IWUSR, root, key, &key_fops);
	if (IS_ERR_OR_NULL(d))
	    goto err_reg;

	d = debugfs_create_file("text", S_IRUGO | S_IWUSR, root, text, &text_fops);
	if (IS_ERR_OR_NULL(d))
	    goto err_reg;

	return true;
	
 err_reg:
	debugfs_remove_recursive(root);
	return false;
}

static ssize_t text_receive ( struct file * file, const char *buff, size_t len, loff_t * off ) {	

	spin_lock (&text_lock);
	
	if (text)
		kfree(text);

	text = (char *) kzalloc (len, GFP_KERNEL);
		
	if (copy_from_user(text + *off, buff, len))
		return -EFAULT;

	spin_unlock (&text_lock);
	
	textlen = len;
	*off += len;
	
	return len;
}

static ssize_t text_send ( struct file * file, char __user *buff, size_t len, loff_t * off ) {

	char * mytext = text ? text : "";
	size_t mysize = text ? textlen : 1;
	
	if (*off >= mysize)
		return 0;
	
	if (*off + len > mysize)
		len = mysize - *off;
	
	if (copy_to_user(buff, mytext + *off, mysize))
		return -EFAULT;
	
	*off += len;
	
	return len;
}

static ssize_t key_receive ( struct file * file, const char *buff, size_t len, loff_t * off ) {	


	switch (len) {
	case KEY_SIZE_8B:
		keylen = KEY_SIZE_8B;
		break;
	case KEY_SIZE_16B:
		keylen = KEY_SIZE_16B;
		break;
	case KEY_SIZE_24B:
		keylen = KEY_SIZE_24B;
		break;
	case KEY_SIZE_32B:
		keylen = KEY_SIZE_32B;
		break;
	default:
		pr_warn("Key length %u is not supported.\n", len);
		*off += len;
		return 0;
	}

	if (*off >= KEY_SIZE_MAX) 
		return 0;
	
	if (*off + len > keylen)
		len = keylen - *off;
	
	spin_lock (&key_lock);
	
	memset(key, 0, KEY_SIZE_MAX);
	
	if (copy_from_user(key + *off, buff, keylen))
		return -EFAULT;

	spin_unlock (&key_lock);
	
	*off += len;
	
	return len;
}

static ssize_t key_send ( struct file * file, char __user *buff, size_t len, loff_t * off ) {

	if (*off >= KEY_SIZE_MAX)
		return 0;
	
	if (*off + len > KEY_SIZE_MAX)
		len = KEY_SIZE_MAX - *off;
	
	if (copy_to_user(buff, key + *off, KEY_SIZE_MAX))
		return -EFAULT;
	
	*off += len;
	
	return len;
}

static int par_open (struct inode * inode, struct file * filep) {

	filep->private_data = inode->i_private;
	
	return 0;
}

/* static ssize_t dev_send (struct file * file, char __user * buff, size_t len, loff_t * off) { */
	
/* 	*off += len; */
	
/* 	return len; */
	
/* } */

static void free_nodes (telem * nodes []) {

	uint i;
	telem * node;
	command * cmd, * temp;
	
	for (i = 0; i < max_node; i++) {

		node = nodes[i];
		
		if (node) {
			
			list_for_each_entry_safe (cmd, temp, &node->cmd_list, elem) {

				node->pending --;
			    list_del(&cmd->elem);
				kfree(cmd);
			}
		}
	}
}

static ssize_t dev_receive ( struct file * file, const char *buff, size_t len, loff_t * off ) {
	
    unsigned int res;
	char * token, * str = "";
	uint i = 0;
	int mode = -1, args = -1, com = -1, jid = -1, times = 1; 
    command * cmd;
	telem * node;
	telem * nodes [max_node];
	
	*off += len;
	
	for (i = 0; i < max_node; i++)
		nodes[i] = NULL;
   	
	strcpy(str, buff);

	i = 0;
		
	while ((token = strsep(&str, ","))) {
			
		if (strcmp(token, "")) {
			
			if (!kstrtou32(token, 10, &res)) {
					
				switch (i) {
					
				case 0:
					com = res;
					break;;
				case 1:
					mode = (int) res;
					break;;
				case 2:
					args = (int) res;
					break;;
				case 3:
					jid = (int) res;
					break;;
				case 4:
				    times = (int) res;
					break;;
				default:
					break;;	
				}
					
				i++;
					
			} else
				pr_err("Invalid test receieved: %s\n", token);
		}	
	}

	if (cmd >= 0) {

		for (i = 0; i < times; i++) {

			cmd = (command *) kzalloc (sizeof(cmd), GFP_KERNEL);
			
			if (!cmd) {
				
				pr_err("Failed to allocate command, aborting.\n");
				free_nodes (nodes);
				return len;
			
			}

			cmd->tnum = com;
			cmd->tmode = mode;
			cmd->args = args;
		   
			node = get_min_node(); /* Must always return a node. */
		
			list_add_tail(&cmd->elem, &node->cmd_list);
			node->pending ++;
			nodes[node->id] = node;
		}
	}

	for (i = 0; i < max_node; i++) {
		
		if (nodes[i]) 
			kthread_run ( run_test, nodes[i], "cryptotest-worker" );
	}
	
	return len;
}

tjob * init_job (telem * node, command * cmd) {
	
	tjob * job = (tjob *) kzalloc(sizeof(tjob), GFP_KERNEL);
	
	if (!job) {
		
		pr_err("Node %u: Error allocating new job.\n", node->id);
		
		return NULL;
		
	} else {
		
		job->parent = node;
		job->tnum = cmd->tnum;
		job->tmode = cmd->tmode;
		job->args = cmd->args;
		job->id = job_id ++;
		
		pr_info("Node %u: New job (%u) for %u.\n", node->id, job->id, job->tnum);
	}
	
	job->data = (tdata * ) kzalloc (sizeof(tdata), GFP_KERNEL);

	if (!job->data) {

		pr_err("%u >> Error allocating job data.\n", job->id);
		kfree(job);

		return NULL;
	}

	if (textlen) {
		
		job->data->text = (char *) kzalloc (textlen, GFP_KERNEL);
		if (!job->data->text) {
			
			pr_err("%u >> Error allocating job text.\n", job->id);
			kfree(job->data);
			kfree(job);

			return NULL;
		}
		
		spin_lock (&text_lock);
		strncpy(job->data->text, text, textlen);
		job->data->txtlen = textlen;
		spin_unlock (&text_lock);
		
	} else {

		pr_err("%u >> No text found, aborting.\n", job->id);
		kfree(job->data);
		kfree(job);

		return NULL;	
	}
    	
	if (job->tnum < CRYPTO_CRC) {
		
		if (keylen) {
			
			job->data->key = (char *) kzalloc (keylen, GFP_KERNEL);
			if (!job->data->key) {
				
				pr_err("%u >> Error allocating job key.\n", job->id);
				kfree(job->data->text);
				kfree(job->data);
				kfree(job);

				return NULL;
			}
			
			spin_lock (&key_lock);
			strncpy(job->data->key, key, keylen);
			job->data->keylen = keylen;
			spin_unlock (&key_lock);
			
		} else {

			pr_err("%u >> No key found, aborting.\n", job->id);
			kfree(job->data->text);
			kfree(job->data);
			kfree(job);

			return NULL;
		} 
	}

	/* Store cmd arguments for decrypt ... */
	
	spin_lock(&node->lock);
	list_add_tail(&job->elem, &node->jobs);
	spin_unlock(&node->lock);
	
	return job;
}

tjob * get_job (telem * node, command * cmd) {
	
	tjob * job;
	
	if ((cmd->tnum == CRYPTO_AES || cmd->tnum == CRYPTO_TDES) && cmd->args == 1) {

		if (cmd->jid >= 0) {
			
			list_for_each_entry(node, &node_list, elem) { 
				
				list_for_each_entry (job, &node->jobs, elem) {
					
					if (job->id == cmd->jid)
						return job;
				}
			}
			
			return NULL;
			
		} else {

			pr_info("Node %u: Bad jid (%d) provided.\n", node->id, cmd->jid);
			return NULL;
		}

	} else
		return init_job( node, cmd );
	
}

static int run_test (void * node_ptr) {
	
	telem * node = (telem *) node_ptr;
	tjob * job;
    command * cmd, * temp;
	int ret = true;

	list_for_each_entry_safe (cmd, temp, &node->cmd_list, elem) {

		pr_info("Node %u: Running command %u (args: %d).\n", node->id, cmd->tnum, cmd->args);

		if (cmd->tnum > CRYPTO_DIVX) {

			pr_err("Node %u: Bad command received %u.\n", node->id, cmd->tnum);
			list_del(&cmd->elem);
			kfree(cmd);
			continue;
		}
		
		job = get_job(node, cmd);

		if (!job) {
			
			pr_err("Node %u: Failed to get job.\n", node->id);
			list_del(&cmd->elem);
			kfree(cmd);
			continue;
		}
		
		switch (job->tnum) 
			{
				
			case CRYPTO_AES:
				{
					switch(job->args) {
					case 0:
						ret = do_aes_encrypt ( job );
						break;;
					case 1:
						ret = do_aes_decrypt ( job );
						break;;
					default:
						ret = do_aes ( job );
					}
				}
				break;;
				
			case CRYPTO_TDES:
				{
					switch(job->args) {
					case 0:
						ret = do_tdes_encrypt ( job );
						break;;
					case 1:
						ret = do_tdes_decrypt ( job );
						break;;
					default:
						ret = do_tdes ( job );
					}
				}
				break;;

			case CRYPTO_CRC:
				{
					switch(job->args) {
					case 0:
						ret = do_crc_update ( job );
						break;;
				    default:
						ret = do_crc_digest ( job );
					}
				}
				break;;
				
			case CRYPTO_DIVX:
				{ 
					ret = do_divx_decomp ( job );
				}
				break;;
			
			default: 
			
				pr_err("Invalid command requested: %u.\n", job->tnum);
				ret = false;
			
			};
	
		if (!ret)
			pr_err("Error running command (%u).\n", job->tnum);
		
		list_del(&cmd->elem);
		kfree(cmd);
	}

	return 1;
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

static int __init crypto_init(void)
{  

	uint i;
	telem * node , * temp;
	
	major = register_chrdev(0, "cryptotest", &fops);
	if ( major < 0 ) {
		
		pr_err("Char device registration failed.\n");
		unregister_chrdev ( major, "cryptotest" );
		
	} else
		pr_info("Char device %d registered.\n", major);

	if (!register_debugfs())
		return -ENOMEM;

	spin_lock_init(&key_lock);
	spin_lock_init(&text_lock);

	for (i = 0; i < max_node; i++) {

		node = (telem *) kzalloc(sizeof(telem), GFP_KERNEL);
		
		if (node) {
		
			spin_lock_init(&node->lock);
			INIT_LIST_HEAD(&node->jobs);
			INIT_LIST_HEAD(&node->cmd_list);
			node->pending = 0;

			list_add_tail(&node->elem, &node_list);
			
		} else {
			
			pr_err("Error allocating node %d.\n", i);
			goto err_gen;
			
		}
	}
	
   	return 0;
	
 err_gen:
	
	list_for_each_entry_safe (node, temp, &node_list, elem) {
		
		list_del(&node->elem);
		kfree(node);
		
	}
	
	debugfs_remove_recursive(root);
	unregister_chrdev ( major, "cryptotest" );
	return -ENOMEM;

}

static void __exit crypto_exit(void)
{

	telem * node, * temp;
	tjob * job;
	
	list_for_each_entry_safe(node, temp, &node_list, elem) {
		
		if (node->pending) {

			list_for_each_entry (job, &node->jobs, elem) {

				list_del(&job->elem);
			    destroy_job(job);

			}

		}
		
		list_del(&node->elem);
		kfree(node);
	}

	debugfs_remove_recursive(root);
	unregister_chrdev ( major, "cryptotest" );
}

module_init(crypto_init);
module_exit(crypto_exit);
