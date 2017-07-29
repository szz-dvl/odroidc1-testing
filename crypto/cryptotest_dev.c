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
static ssize_t size_receive ( struct file * file, const char *buff, size_t len, loff_t * off );
static ssize_t size_send ( struct file * file, char __user *buff, size_t len, loff_t * off );
static tjob * init_job (telem * node, command * cmd);
static tjob * get_job (telem * node, command * cmd);
static int run_test (void * node_ptr);
static void free_nodes (telem * nodes []);
static telem * get_min_node (void);
static void destroy_texts (void);
static tjob * get_job_by_id ( uint jid );
static text * get_text_by_id ( uint tid );
static bool add_text ( void );
static bool update_text ( uint tid );
static bool remove_text ( uint tid );
static bool print_texts ( void );

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

static struct file_operations size_fops = {
	.write = size_receive,
	.read = size_send,
	.open = par_open
};

LIST_HEAD(node_list);
LIST_HEAD(texts_list);

static spinlock_t text_lock;
static spinlock_t key_lock;
static spinlock_t size_lock;

static unsigned int major, job_id = 0, text_id = 0;
struct dentry *root;

static unsigned int keylen, textlen;
static char key [KEY_SIZE_MAX];
static char * text_data;
static uint mode;

static unsigned long long max_size = UINT_MAX;
static unsigned long long glob_size = 4 * 1024;
static char hr_size [32] = "4K";

uint verbose = 0;
uint text_cnt = 0;

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

	d = debugfs_create_u32("text_id", S_IRUGO, root, (u32 *)&text_id);
	if (IS_ERR_OR_NULL(d))
	    goto err_reg;

	d = debugfs_create_u32("text_cnt", S_IRUGO, root, (u32 *)&text_cnt);
	if (IS_ERR_OR_NULL(d))
	    goto err_reg;

	d = debugfs_create_u32("keylen", S_IRUGO, root, (u32 *)&keylen);
	if (IS_ERR_OR_NULL(d))
	    goto err_reg;

	d = debugfs_create_u32("verbose", S_IRUGO | S_IWUSR, root, (u32 *)&verbose);
	if (IS_ERR_OR_NULL(d))
	    goto err_reg;

	d = debugfs_create_u32("mode", S_IRUGO | S_IWUSR, root, (u32 *)&mode);
	if (IS_ERR_OR_NULL(d))
	    goto err_reg;

	d = debugfs_create_file("glob_size", S_IRUGO | S_IWUSR, root, hr_size, &size_fops);
	if (IS_ERR_OR_NULL(d))
	    goto err_reg;
	
	d = debugfs_create_file("key", S_IRUGO | S_IWUSR, root, key, &key_fops);
	if (IS_ERR_OR_NULL(d))
	    goto err_reg;

	d = debugfs_create_file("text", S_IRUGO | S_IWUSR, root, text_data, &text_fops);
	if (IS_ERR_OR_NULL(d))
	    goto err_reg;

	return true;
	
 err_reg:
	debugfs_remove_recursive(root);
	return false;
}

static void free_spec ( tjob * job ) {
	
	switch (job->tnum)
		{

		case CRYPTO_AES:
			{
				skcip_d * spec_data = job->data->spec;
				struct ablkcipher_request * ereq;
				struct ablkcipher_request * dreq;
				struct scatterlist * aux;

				if (spec_data->ereq) {

					ereq = &spec_data->ereq->creq;
					aux = ereq->src;

					while (aux) {
						
						if (sg_dma_address(aux)) {
							
							dma_free_coherent(NULL, sg_dma_len(aux), sg_virt(aux), sg_dma_address(aux));
							aux = sg_next(aux);
								
						} else
							break;
						
					}

					sg_free_table(&spec_data->esrc);

					aux = ereq->dst;
					while (aux) {
						
						if (sg_dma_address(aux)) {
							
							dma_free_coherent(NULL, sg_dma_len(aux), sg_virt(aux), sg_dma_address(aux));
							aux = sg_next(aux);
							
						} else
							break;
						
					}

					sg_free_table(&spec_data->edst);

					if (spec_data->ereq->giv)
						kfree(spec_data->ereq->giv);
					
					skcipher_givcrypt_free (spec_data->ereq);
				}

				if (spec_data->dreq) {

					dreq = &spec_data->dreq->creq;
					aux = dreq->dst;
						
					while (aux) {

						if (sg_dma_address(aux)) {
							
							dma_free_coherent(NULL, sg_dma_len(aux), sg_virt(aux), sg_dma_address(aux));
							aux = sg_next(aux);
								
						} else
							break;
						
					}

					sg_free_table(&spec_data->ddst);
					
					skcipher_givcrypt_free (spec_data->dreq);
				}

				if (spec_data->tfm)
					crypto_free_ablkcipher (spec_data->tfm);
				
				kfree(job->data->spec);
			}
		    return;
				
		case CRYPTO_TDES:
			return;

		case CRYPTO_CRC:
			return;
			
		case CRYPTO_DIVX:
			return;
			
		default:
			return;
		}
}


void destroy_job ( tjob * job ) {
	
	list_del(&job->elem);

	spin_lock (&job->parent->lock);
	job->parent->pending --;
	spin_unlock (&job->parent->lock);
	
	free_spec(job);
	
	if (job->data->key)
		kfree(job->data->key);
	
	kfree(job->data);
	kfree(job);
}

static ssize_t size_receive ( struct file * file, const char *buff, size_t len, loff_t * off ) {

	char * my_size = hr_size;
	
	if (*off >= 32) 
		return 0;
	
	if (*off + len > 32)
		len = 32 - *off;

	spin_lock (&size_lock);

	memset(my_size, 0, sizeof(hr_size));
	
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

	spin_unlock (&size_lock);
	
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

static ssize_t text_receive ( struct file * file, const char *buff, size_t len, loff_t * off ) {	

	spin_lock (&text_lock);
	
	if (text_data)
		kfree(text_data);

    text_data = (char *) kzalloc (len, GFP_KERNEL);
		
	if (copy_from_user(text_data + *off, buff, len))
		return -EFAULT;

	spin_unlock (&text_lock);
	
	textlen = len;
	*off += len;
	
	return len;
}

static ssize_t text_send ( struct file * file, char __user *buff, size_t len, loff_t * off ) {

	char * mytext = text_data ? : "";
	size_t mysize = text_data ? textlen : 1;
	
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

	if (*off >= KEY_SIZE_MAX) 
		return 0;
	
	spin_lock (&key_lock);

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

	if (*off + len > keylen)
		len = keylen - *off;
	
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

static void free_nodes (telem * nodes []) {

	uint i;
	telem * node;
	command * cmd, * temp;
	
	for (i = 0; i < max_node; i++) {

		node = nodes[i];
		
		if (node) {
			
			list_for_each_entry_safe (cmd, temp, &node->cmd_list, elem) {

			    list_del(&cmd->elem);
				kfree(cmd);
			}

			nodes[i] = NULL;
		}
	}
}

static ssize_t dev_receive ( struct file * file, const char *buff, size_t len, loff_t * off ) {
	
    unsigned int res;
	char * token, * str = "";
	uint i = 0;
	int args = -1, com = -1, jid = -1, times = 1; 
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
					args = (int) res;
					break;;
				case 2:
					jid = (int) res;
					break;;
				case 3:
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
			cmd->args = args;
			cmd->jid = jid;
			
			node = get_min_node(); /* Must always return a node. */
		
			list_add_tail(&cmd->elem, &node->cmd_list);
			nodes[node->id] = node;
		}
	}

	for (i = 0; i < max_node; i++) {
		
		if (nodes[i]) 
			kthread_run ( run_test, nodes[i], "cryptotest-worker" );
	}
	
	return len;
}

static void destroy_texts ( void ) {

	text * txt;

	text_for_each (txt) { 
					
		list_del(&txt->elem);
		kfree(txt->text);
		kfree(txt);
	}

}

static tjob * init_job (telem * node, command * cmd) {
	
	tjob * job;

	if (no_text) {
		
		pr_err("Node %u: No data found, aborting.\n", node->id);
		return NULL;
	}
	
	job = (tjob *) kzalloc(sizeof(tjob), GFP_KERNEL);
	
	if (!job) {
		
		pr_err("Node %u: Error allocating new job.\n", node->id);
		
		return NULL;
		
	} else {
		
		job->parent = node;
		job->tnum = cmd->tnum;
		job->tmode = mode;
		job->args = cmd->args;
		job->id = job_id ++;
		
		pr_info("Node %u: New job (%u) for %u.\n", node->id, job->id, job->tnum);
	}

	if ( ((job->tmode > CRYPTO_AES_CTR) && job->tnum == CRYPTO_AES) ||
		 ((job->tmode < CRYPTO_TDES_CBC || job->tmode > CRYPTO_TDES_ECB) && job->tnum == CRYPTO_TDES)) { 

		pr_err("%u >> Bad mode found, aborting.\n", job->id);
		kfree(job);

		return NULL;

	}
	
	job->data = (tdata * ) kzalloc (sizeof(tdata), GFP_KERNEL);

	if (!job->data) {

		pr_err("%u >> Error allocating job data.\n", job->id);
		kfree(job);

		return NULL;
	}

	spin_lock (&size_lock);
	job->data->nbytes = glob_size;
	spin_unlock (&size_lock);

	job->data->text_num = text_cnt;
    	
	if (job->tnum < CRYPTO_CRC) {
		
		if (keylen) {
			
			job->data->key = (char *) kzalloc (keylen, GFP_KERNEL);
			if (!job->data->key) {
				
				pr_err("%u >> Error allocating job key.\n", job->id);
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
			kfree(job->data);
			kfree(job);

			return NULL;
		} 
	}
	
	spin_lock(&node->lock);
	node->pending ++;
	list_add_tail(&job->elem, &node->jobs);
	spin_unlock(&node->lock);
	
	pr_info ("%u >> New job created, max length: %s (%u Bytes), text_num: %u", job->id, hr_size, job->data->nbytes, job->data->text_num);
	return job;
}

static tjob * get_job_by_id ( uint jid ) {

	telem * node;
	tjob * job;
	
	list_for_each_entry(node, &node_list, elem) { 
				
		list_for_each_entry (job, &node->jobs, elem) {
			
			if (job->id == jid) 
				return job;
		}
	}

	return NULL;
}

static tjob * get_job (telem * node, command * cmd) {
	
	if ((cmd->tnum == CRYPTO_AES || cmd->tnum == CRYPTO_TDES) && cmd->args == 1) {

		if (cmd->jid >= 0) 
			return get_job_by_id (cmd->jid);
		
		else {

			pr_info("Node %u: Bad jid (%d) provided.\n", node->id, cmd->jid);
			return NULL;
		}
		
	} else
		return init_job( node, cmd );
}

static text * get_text_by_id ( uint tid ) {

	text * txt;
	
    text_for_each (txt) { 
					
		if (txt->id == tid) 
			return txt;
		
	}

	return NULL;
}

static bool add_text ( void ) {

	text * txt = (text *) kzalloc(sizeof(text), GFP_KERNEL);

	if (!txt) {

		pr_err("%s: Error allocating new text.\n", __func__);
		return false;
	}
		
	spin_lock (&text_lock);

	txt->text = (char *) kzalloc (textlen, GFP_KERNEL);
	
	if (!txt->text) {
			
		pr_err("%s: Error allocating new text.\n", __func__);
		kfree(txt);
	    return false;
	}
		
	
	strncpy(txt->text, text_data, textlen);
    txt->len = textlen;
	txt->id = text_id ++;
	
	spin_unlock (&text_lock);

    text_add(txt);		
	text_cnt ++;
	
	return true;
}

static bool update_text ( uint tid ) {

	text * txt = get_text_by_id (tid);

	if (!txt) {

		pr_err("%s: Bad tid (%u) provided.\n", __func__, tid);
		return false;
	}

	kfree (txt->text);
	
	spin_lock (&text_lock);
	
	txt->text = (char *) kzalloc (textlen, GFP_KERNEL);
	
	if (!txt->text) {
			
		pr_err("%s: Error allocating new text memory.\n", __func__);
		txt->len = 0;
	    return false;
	}
		
	
	strncpy(txt->text, text_data, textlen);
    txt->len = textlen;
	spin_unlock (&text_lock);	

	return true;
}

static bool remove_text ( uint tid ) {

	text * txt = get_text_by_id (tid);;

	if (!txt) {

		pr_err("%s: Bad tid (%u) provided.\n", __func__, tid);
		return false;
	}

	list_del(&txt->elem);
	kfree (txt->text);
	kfree (txt);
	text_cnt --;

	return true;
	
}

static bool print_texts ( void ) {

	text * txt;
	uint bytes = 0;
	
    text_for_each(txt) { 
					
		pr_info("%2u: (%5u Bytes) %.128s %s\n", txt->id, txt->len, txt->text, txt->len > 128 ? "\e[44;1m...\e[0m" : "");
		bytes += txt->len;
	}

	if (bytes)
		pr_info("\nTOTAL: %u Bytes.\n", bytes);

	return true;
}

static int run_test (void * node_ptr) {
	
	telem * node = (telem *) node_ptr;
	tjob * job = NULL;
    command * cmd, * temp;
	int ret = true;

	list_for_each_entry_safe (cmd, temp, &node->cmd_list, elem) {

		pr_info("Node %u: Running command %u (args: %d)\n", node->id, cmd->tnum, cmd->args);

		if (cmd->tnum > PRINT_TEXTS) {

			pr_err("Node %u: Bad command received %u.\n", node->id, cmd->tnum);
			list_del(&cmd->elem);
			kfree(cmd);
			continue;
		}

		if (cmd->tnum < TEXT_ADD) {

			job = get_job(node, cmd);

			if (!job) {
				
				pr_err("Node %u: Failed to get job.\n", node->id);
				list_del(&cmd->elem);
				kfree(cmd);
				continue;
			}
		}
		
		switch (cmd->tnum) 
			{
				
			case CRYPTO_AES:
				{
					switch(cmd->args) {
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
					switch(cmd->args) {
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
					switch(cmd->args) {
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

				/* Text management */

			case TEXT_ADD:
				{ 
					ret = add_text ();
				}
				break;;

			case TEXT_UPDATE:
				{ 
					ret = update_text ( cmd->args );
				}
				break;;

			case TEXT_REMOVE:
				{ 
					ret = remove_text ( cmd->args );
				}
				break;;

			case PRINT_TEXTS:
				{ 
					ret = print_texts ();
				}
				break;;
				
			default: 
				
				pr_err("Invalid command requested: %u.\n", cmd->tnum);
				ret = false;
			
			};
	
		if (!ret)
			pr_err("Error running command (%u).\n", cmd->tnum);
		
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
	spin_lock_init(&size_lock);
	
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
	tjob * job, * tmp;
	
	list_for_each_entry_safe(node, temp, &node_list, elem) {
		
		if (node->pending) {

			list_for_each_entry_safe (job, tmp, &node->jobs, elem) 
			    destroy_job(job);
		}
		
		list_del(&node->elem);
		kfree(node);
	}

	destroy_texts();
	debugfs_remove_recursive(root);
	unregister_chrdev ( major, "cryptotest" );
}

module_init(crypto_init);
module_exit(crypto_exit);
