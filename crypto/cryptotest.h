#include <linux/kthread.h>
#include <linux/jiffies.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/dmaengine.h>
#include <linux/dma-mapping.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/debugfs.h>
#include <linux/string.h>
#include <linux/crypto.h>
#include <linux/device.h>
#include <crypto/aes.h>
#include <../crypto/internal.h>
#include <crypto/skcipher.h>

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

typedef struct skcipher_data {

	struct skcipher_givcrypt_request * ereq;
	struct skcipher_givcrypt_request * dreq;
    struct crypto_ablkcipher * tfm;

	struct scatterlist esrc, edst, ddst;
	
} skcip_d;

typedef struct ablkcipher_data {

	struct ablkcipher_request * ereq;
	struct ablkcipher_request * dreq;
	struct crypto_ablkcipher * tfm;

	struct scatterlist esrc, edst, ddst;
	
} ablk_d;

typedef struct ahash_data {

	struct ahash_request * req;
	struct crypto_hash * tfm;
	
} ahash_d;

typedef struct acomp_data {
	
    struct acomp_req * req;
	struct crypto_acomp * tfm;

} acomp_d;
	
typedef struct cmd_grabber {
	
	struct list_head elem;
	
	ttype tnum;
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

typedef struct test_data {
	
	char * text;
	char * key;
	
	klen keylen;
	uint txtlen;
	
	void * spec;
	
} tdata;

typedef struct test_job {
	
	uint id;
	telem * parent;
	
	const char * tname;
	
	tdata * data;
	
	ttype tnum;
    tmode tmode;

	uint args;

	struct list_head elem;
	
	unsigned long stime;	
	
} tjob;


/* Public */
void destroy_job ( tjob * job );
bool valid_state ( tjob * job );
	
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

/* Public params */
extern uint verbose;
