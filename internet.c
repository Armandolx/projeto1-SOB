#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <asm/uaccess.h>
#include <crypto/hash.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <crypto/rng.h>
#include <crypto/md5.h>
#include <crypto/sha.h>
#include <crypto/internal/skcipher.h>
#include <linux/jiffies.h>
#include <crypto/skcipher.h>
#include <crypto/aead.h>
#include <crypto/scatterwalk.h>
#include <crypto/if_alg.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/net.h>
#include <net/sock.h>
#include <linux/string.h>


MODULE_LICENSE("GPL");

struct tcrypt_result {
	struct completion completion;
	int err;
};

static void cipher_work_done(struct crypto_async_request *req, int err)
{
	struct tcrypt_result *res = req->data;

    printk("cipher_work_done called: %d\n", err);

	if (err == -EINPROGRESS)
		return;

	res->err = err;
	complete(&res->completion);
}


void test_ciphers(void)
{

    struct crypto_aead *tfm = NULL;
    //struct crypto_blkcipher *tfm = NULL;
    //struct aead_desc desc;
    struct aead_request *req;

    unsigned char key[16] = {
        0x5c, 0x95, 0x64, 0x42, 0x00, 0x82, 0x1c, 0x9e,
        0xd4, 0xac, 0x01, 0x83, 0xc4, 0x9c, 0x14, 0x97
    };
    unsigned int ivsize;
    int ret;
    struct scatterlist plaintext[1];
    struct scatterlist ciphertext[1];
    struct scatterlist hmactext[1];
    unsigned char *plaindata = NULL;
    unsigned char *cipherdata = NULL;
    unsigned char *hmacdata = NULL;
    unsigned char *ivp = NULL;
    unsigned char *keyp = NULL;
    int i;
    unsigned char d;
    unsigned char out[160];
    struct tcrypt_result result;

    printk("Test ciphers executing...\n");

	//aead_request_set_assoc(req, hmactext, 16);
	aead_request_set_ad(req, 16);

    tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
    printk("Asking for AEAD say %p\n", tfm);

    reinit_completion(&result.completion);

    req = aead_request_alloc(tfm, GFP_KERNEL);
	if (!req) goto out;


    aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                              cipher_work_done, &result);

    crypto_aead_clear_flags(tfm, ~0);


    ret = crypto_aead_setauthsize(tfm, 16); // authsize is hmac?


    printk("Allocating buffers, setting input\n");


    ivsize = crypto_aead_ivsize(tfm);
    if (ivsize != 12) {
        printk("ivsize is not 12 %d\n", ivsize);
        // lets continue anyway, and see what ivsize 16 produces
    }

    plaindata  = kmalloc(512 + 512, GFP_KERNEL);
    cipherdata = kmalloc(512 + 512, GFP_KERNEL);
    hmacdata   = kmalloc(16+128, GFP_KERNEL);
    ivp        = kmalloc(ivsize + 128, GFP_KERNEL);
    keyp       = kmalloc(sizeof(key) + 128, GFP_KERNEL);

    if (!plaindata || !cipherdata || !hmacdata || !ivp || !keyp) goto out;

    // Fill source with 00, 01, 02, ...
    for (i = 0, d = 0; i < 512; i++, d++)
        plaindata[i] = d;
    memset(cipherdata, 0, 512);
    memset(hmacdata, 0, 16);
    memset(ivp, 0, ivsize);
    memcpy(keyp, key, sizeof(key));

    printk("Setting key\n");
    ret = crypto_aead_setkey(tfm, keyp, sizeof(key));
    if (ret) goto out;

    // Fill iv with a8, a9, aa, ...
    for (i = 0,d=0xa8; i < 12; i++, d++)
        ivp[i] = d;

    sg_init_one(&plaintext[0],  plaindata,  512);
    sg_init_one(&ciphertext[0], cipherdata, 512);
    sg_init_one(&hmactext[0],   hmacdata,   16);



    printk("Calling crypto...\n");



    aead_request_set_crypt(req, plaintext, ciphertext, 512, ivp);

    ret = crypto_aead_encrypt(req);

    printk("cipher call returns %d (EBUSY is %d)\n",
           ret, -EBUSY);

    switch (ret) {
    case 0: // Verification failed
        printk(KERN_ERR "alg: aead: failed ret was 0\n");
        break;
    case -EINPROGRESS:
    case -EBUSY:
        ret = wait_for_completion_interruptible(
                                                &result.completion);
        if (!ret && !(ret = result.err)) {
            reinit_completion(&result.completion);
            break;
        }
    case -EBADMSG:
        /* fall through */
    default:
        printk(KERN_ERR "alg: aead: failed ret was %d\n", ret);
    }

    printk("Cipherdata result:\n");
    *out = 0;
    for (i = 0; i < 512; i++) {

        snprintf((char*)out, sizeof(out), "%s 0x%02x", out, cipherdata[i]);
        if ((i % 8)==7) {
            printk("%s\n", out);
            *out = 0;
        }
    }
    printk("%s\nMAC output:", out);
    *out = 0;
    for (i = 0; i < 16; i++) {
        snprintf((char *)out, sizeof(out), "%s 0x%02x", out, hmacdata[i]);
    }
    printk("%s\n", out);

 out:
    printk("Test ciphers finished.\n");

    if (req) aead_request_free(req);
    if (!IS_ERR(tfm)) crypto_free_aead(tfm);
    if (plaindata) kfree(plaindata);
    if (cipherdata) kfree(cipherdata);
    if (hmacdata) kfree(hmacdata);
    if (ivp) kfree(ivp);
    if (keyp) kfree(keyp);
}

int init_module(void)
{
	
	printk(KERN_WARNING "inicialização\n");
	test_ciphers();
	
	return 0;
}

void cleanup_module(void)
{
	printk(KERN_WARNING "Goodbye world 1.\n");
}

