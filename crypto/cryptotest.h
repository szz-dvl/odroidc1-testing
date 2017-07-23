#include <linux/kthread.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/hardirq.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/debugfs.h>
#include <linux/string.h>
#include <linux/crypto.h>
#include <crypto/aes.h>

typedef enum test_type {

	CRYPTO_AES,
	CRYPTO_TDES,
	CRYPTO_CRC,
	CRYPTO_DIVX
   
} ttype;

typedef enum test_mode {

	CRYPTO_AES_CBC,
	CRYPTO_AES_ECB,
	CRYPTO_AES_CTR,
	CRYPTO_TDES_CBC,
	CRYPTO_TDES_ECB
	
} tmode;

typedef enum key_sizes {

	KEY_SIZE_8B = 8,
	KEY_SIZE_16B = AES_KEYSIZE_128,
	KEY_SIZE_24B = AES_KEYSIZE_192,
	KEY_SIZE_32B = AES_KEYSIZE_256,
	KEY_SIZE_MAX = AES_KEYSIZE_256
	
} klen;

typedef struct cmd_grabber {
	
	struct list_head elem;
	
	ttype tnum;
    int tmode;
	int args;
	int jid;
	
} command;

typedef struct test_elem {
	
	spinlock_t lock;

	uint id;
	
	struct list_head jobs;
	struct list_head elem;

	struct list_head cmd_list;
	
	unsigned int pending;
	
} telem;

typedef struct test_job {
	
	struct list_head elem;
	
	uint id;

	const char * tname;
	
	char * text;
	char * key;

	klen keylen;
	uint txtlen;
	
	char * result;

	struct ablkcipher_request * ablk_req;
	struct crypto_blkcipher * ablk_tfm;

	ttype tnum;
    int tmode;
	
	unsigned long stime;	
	
} tjob;

#define MAX_KEY_SIZE AES_KEYSIZE_256 

/* AES */
bool do_aes_encrypt ( tjob * job );
bool do_aes_decrypt ( tjob * job );
bool do_aes ( tjob * job ); /* Encrypt + Decrypt + Compare results */

/* TDES */
bool do_tdes_encrypt ( tjob * job );
bool do_tdes_decrypt ( tjob * job );
bool do_tdes ( tjob * job ); /* Encrypt + Decrypt + Compare results */

/* CRC */
bool do_crc_digest ( tjob * job );
bool do_crc_update ( tjob * job );

/* DIVX*/
bool do_divx_decomp ( tjob * job );
