#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <asm/uaccess.h>
#include <crypto/hash.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
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

/* tie all data structures together */
struct skcipher_def {
    struct scatterlist sg;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct tcrypt_result result;
};

/* Callback function */
static void test_skcipher_cb(struct crypto_async_request *req, int error)
{

    struct tcrypt_result *result = req->data;

    if (error == -EINPROGRESS)
	{
		pr_info("entrou erro");
		return;
	}
      pr_info("passou aqui  test_skcipher_cb");
    result->err = error;
    complete(&result->completion);
    pr_info("Encryption finished successfully\n");
}

/* Perform cipher operation */
static unsigned int test_skcipher_encdec(struct skcipher_def *sk,
                     int enc)
{
	
    int rc = 0;

    if (enc)
	{
		//pr_info("VALOR SK ANTES %s\n",sk->req);
		rc = crypto_skcipher_encrypt(sk->req);
		pr_info("RC IF ENC %d\n",rc);
		//pr_info("VALOR SK DEPOIS %s\n",sk->req);
	}
        
    else
	{
		rc = crypto_skcipher_decrypt(sk->req);
		pr_info("RC ELSE ENC %d\n",rc);
	}
        


	pr_info("RC %d\n",rc);
    switch (rc) {
    case 0:
        break;
    case -EINPROGRESS:
    case -EBUSY:
        rc = wait_for_completion_interruptible(
            &sk->result.completion);
        if (!rc && !sk->result.err) {
            reinit_completion(&sk->result.completion);
            break;
        }
    default:
        pr_info("skcipher encrypt returned with %d result %d\n",
            rc, sk->result.err);
        break;
    }
    init_completion(&sk->result.completion);

    return rc;
}

/* Initialize and trigger cipher operation */
static int test_skcipher(void)
{
 struct skcipher_def sk;
    struct crypto_skcipher *skcipher = NULL;
    struct skcipher_request *req = NULL;
    char *scratchpad = NULL;
    char *ivdata = NULL;
	char *buffer = kmalloc(16, GFP_KERNEL);;//MARCADO
	char *buffer2 = kmalloc(16, GFP_KERNEL);;//MARCADO
    unsigned char key[32];
	unsigned char out[160];
    int ret = -EFAULT;
	int i;

    skcipher = crypto_alloc_skcipher("ecb(aes)", 0, 0);//cbc- -aesni
    if (IS_ERR(skcipher)) {
        pr_info("could not allocate skcipher handle\n");
        return PTR_ERR(skcipher);
    }

    req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!req) {
        pr_info("could not allocate skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }

    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                      test_skcipher_cb,
                      &sk.result);

    /* AES 256 with random key */ 
    get_random_bytes(&key, 32); //Mudar isso para a nossa propria chave
	pr_info("KEY GERADA %.2x",key);
    if (crypto_skcipher_setkey(skcipher, key, 32)) {
        pr_info("key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }

    /* IV will be random */
    ivdata = kmalloc(16, GFP_KERNEL);
    if (!ivdata) {
        pr_info("could not allocate ivdata\n");
        goto out;
    }
    get_random_bytes(ivdata, 16);

    /* Input data will be random */
	scratchpad = kmalloc(16, GFP_KERNEL);
   /* scratchpad = kmalloc(16, GFP_KERNEL);

	pr_info("INPUT DATA ANTES %02x",scratchpad);
    if (!scratchpad) {
        pr_info("could not allocate scratchpad\n");
        goto out;
    }
    get_random_bytes(scratchpad, 16);
	pr_info("INPUT DATA DEPOIS %02x",scratchpad);*/

	if (!scratchpad) {
        pr_info("could not allocate scratchpad\n");
        goto out;
    }

	strcpy(scratchpad,"8888888888888888");//9999999999999999
	for(i =0; i< strlen(scratchpad);i++)
	{
		pr_info("SCRATCH1 %.2x \n",scratchpad[i]);
	}

	pr_info("SCRATCH1 string %s \n",scratchpad);
    sk.tfm = skcipher;
    sk.req = req;

    /* We encrypt one block */
    sg_init_one(&sk.sg, scratchpad, 16); //

	sg_copy_to_buffer (&sk.sg, 1, buffer, 16);
	pr_info("buffer antes %s\n",buffer);
	
		//pr_info("Sksg antes %02x \n",sk.sg);
	
	//pr_info("sksg antes %02x \n",sk.sg);
    skcipher_request_set_crypt(req, &sk.sg, &sk.sg, 16, ivdata); //tem &
    init_completion(&sk.result.completion);

	
		pr_info("Sksg depois %.2x \n",sk.sg);
	

	sg_copy_to_buffer (&sk.sg, 1, buffer, 16);



	pr_info("buffer depois %s\n",buffer);

	//pr_info("sksg depois %02x \n",sk.sg);

    /* encrypt data */
    ret = test_skcipher_encdec(&sk, 1);

	sg_copy_to_buffer (&sk.sg, 1, buffer, 16);
	pr_info("buffer depois do ret %.2x\n",buffer);
	for(i=0;i<16;i++)
	{
		printk(KERN_INFO "bufferLOOP depois do ret %02x\n",(unsigned char) (buffer[i]));
	}


	//sg_copy_from_buffer (&sk.sg, 1, buffer, 16);

    if (ret)
	{
		pr_info("VAI PRO OUT \n");
		 goto out;
	}
	else
	{
		pr_info("SCRATCH2 %02x \n",scratchpad);
		
	}

	//DESCRYPT

	skcipher = crypto_alloc_skcipher("ecb(aes)", 0, 0);//cbc- -aesni
    if (IS_ERR(skcipher)) {
        pr_info("could not allocate skcipher handle\n");
        return PTR_ERR(skcipher);
    }

    req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!req) {
        pr_info("could not allocate skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }

    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                      test_skcipher_cb,
                      &sk.result);

	if (crypto_skcipher_setkey(skcipher, key, 32)) {
        pr_info("key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }


    sk.tfm = skcipher;
    sk.req = req;

    /* We encrypt one block */
    //sg_init_one(&sk.sg, buffer, 16); //


    skcipher_request_set_crypt(req, &sk.sg, &sk.sg, 16, ivdata); //tem &
    init_completion(&sk.result.completion);


	ret = test_skcipher_encdec(&sk, 0);

	sg_copy_to_buffer (&sk.sg, 1, buffer2, 16);


	pr_info("DECRYPTbuffer Resultado? %s\n",buffer2);

	for(i=0;i<16;i++)
	{
		printk(KERN_INFO "DECRYPTbufferLOOP depois do ret %02x\n",(unsigned char) (buffer2[i]));
	}

    if (ret)
	{
		pr_info("VAI PRO OUT \n");
		 goto out;
	}
	else
	{
		pr_info("SCRATCH2 %02x \n",scratchpad);
		
	}

    *out = 0;
    for (i = 0; i < 512; i++) {
	
        snprintf((char*)out, sizeof(out), "%s 0x%02x", out, scratchpad[i]);
        if ((i % 8)==7) {
           // pr_info("%02x\n", out);
            *out = 0;
        }
    }
    
       

    pr_info("Encryption triggered successfully 1\n");

out:
	
    if (skcipher)
	{
		pr_info("entrou no OUT skcipher\n");
		crypto_free_skcipher(skcipher);
	}    
    if (req)

	{
		pr_info("entrou no OUT skcipher2\n");
        	skcipher_request_free(req);
	}

    if (ivdata)

	{
		pr_info("entrou no OUT skcipher3\n");
	 	kfree(ivdata);
	}
       
    if (scratchpad)
	{
		pr_info("entrou no OUT skcipher4\n");
	        kfree(scratchpad);
	}

    return ret;
   
}

int init_module(void)
{
	
	printk(KERN_WARNING "inicialização\n");
	test_skcipher();
	
	return 0;
}

void cleanup_module(void)
{
	printk(KERN_WARNING "Goodbye world 1.\n");
}

