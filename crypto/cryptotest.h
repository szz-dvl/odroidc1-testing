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
#include <crypto/hash.h>

typedef enum test_type {
	
	CRYPTO_AES,
	CRYPTO_TDES,
	CRYPTO_CRC,
	CRYPTO_DIVX,

	/* Text management */

	TEXT_ADD,
	TEXT_UPDATE,
	TEXT_REMOVE,
	PRINT_TEXTS
	
} ttype;

typedef enum test_mode {
	
	CRYPTO_AES_ECB,
	CRYPTO_AES_CBC,
	CRYPTO_AES_CTR,
	CRYPTO_DES_ECB,
	CRYPTO_DES_CBC,
	CRYPTO_DDES_ECB,
	CRYPTO_DDES_CBC,
	CRYPTO_TDES_ECB,
	CRYPTO_TDES_CBC,

	/* To save arguments */
	
	CRYPTO_CRC_UPDT,
	CRYPTO_CRC_DIGST,
	CRYPTO_CRC_IMPORT,
	CRYPTO_CRC_EXPORT
	
} tmode;

typedef enum key_sizes {
	
	KEY_SIZE_8B = 8,
	KEY_SIZE_16B = AES_KEYSIZE_128,
	KEY_SIZE_24B = AES_KEYSIZE_192,
	KEY_SIZE_32B = AES_KEYSIZE_256,
	KEY_SIZE_MAX = AES_KEYSIZE_256
	
} klen;

/* AES */
typedef struct skcipher_data {

	struct skcipher_givcrypt_request * ereq;
	struct skcipher_givcrypt_request * dreq;
    struct crypto_ablkcipher * tfm;

	struct sg_table esrc, edst, ddst;
	
} skcip_d;

/* TDES */
typedef struct ablkcipher_data {

    struct ablkcipher_request * ereq;
    struct ablkcipher_request * dreq;
    struct crypto_ablkcipher * tfm;

	struct sg_table esrc, edst, ddst;
	
} ablk_d;

typedef struct ahash_updt {

	struct sg_table src;
	struct list_head elem;

} crc_updt;
	
/* CRC */
typedef struct ahash_data {

	struct ahash_request * req;
	struct crypto_ahash * tfm;

	struct list_head updates;
	
	uint updt_cnt;
	
} ahash_d;

/* DIVX */
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

typedef struct text_data {

	uint id;
	char * text;
	uint len;

	struct list_head elem;

} text;
	
typedef struct test_data {
	
	
	char * key;
	klen keylen;
	
	uint text_num;

	uint nbytes;
	
    void * spec;
	
} tdata;

typedef struct test_job {
	
	uint id;
	telem * parent;
	
	const char * tname;
	
	tdata * data;
	
	ttype tnum;
    tmode tmode;
	
	int args;
	
	struct list_head elem;
	
	unsigned long stime;	
	
} tjob;


/* Public */
void destroy_job ( tjob * job );
bool job_map_texts ( tjob * job );
bool job_map_text ( tjob * job, text * txt, struct scatterlist * src, struct scatterlist * dst );
bool sg_dma_map ( tjob * job, struct scatterlist * sg, uint len);
text * get_text_by_id ( uint tid );

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
bool do_crc_export ( tjob * job );
bool do_crc_import ( tjob * job );

/* DIVX*/
bool do_divx_decomp ( tjob * job );

/* Public params */
extern uint verbose, text_cnt;
extern struct list_head texts_list;

#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"

#define text_for_each(txt)											\
    text * aux__;													\
	list_for_each_entry_safe(txt, aux__, &texts_list, elem)

#define text_add(txt)							\
    list_add_tail (&txt->elem, &texts_list);

#define no_text									\
    list_empty_careful (&texts_list)

#define sg_for_each(sgl, sg)					\
	uint i__;									\
	for_each_sg(sgl, sg, sg_nents(sgl), i__)

/* Already initialized sg lists must be provided, destructive operation on pointers.*/
#define sg_multi_each(src, dst)									\
	for (; src || dst; src = sg_next(src), dst = sg_next(dst))
	

extern uint sequence;
