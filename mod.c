/*
	Armando Dalla Costa Neto,                               	15118029
        Mateus Talzzia Diogo,                                     	15147861
        Matheus Augusto Cremonez Guimarães,       			15004336
	Leonardo Borges Bergamo,					15251275
       	Paulo Vinicius Martimiano de Oliveira,             		15149313
        Rafael Mont’Alverne de Souza,                         		15078371



*/





#include <linux/moduleparam.h>
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
#include <linux/init.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/init.h>           // Macros used to mark up functions e.g. __init __exit
#include <linux/module.h>         // Core header for loading LKMs into the kernel
#include <linux/device.h>         // Header to support the kernel Driver Model
#include <linux/kernel.h>         // Contains types, macros, functions for the kernel
#include <linux/fs.h>             // Header for the Linux file system support
#include <asm/uaccess.h>          // Required for the copy to user function

#define  DEVICE_NAME "ebbchar"    ///< The device will appear at /dev/ebbchar using this value
#define  CLASS_NAME  "ebb"        ///< The device class -- this is a character device driver

MODULE_LICENSE("GPL");            ///< The license type -- this affects available functionality
MODULE_AUTHOR("Armando C. - Mateus T. - Matheus G. - Leonardo B. - Paulo O. - Rafael M. ");    ///< The author -- visible when you use modinfo
MODULE_DESCRIPTION("A Crypt and Decrypt driver in Linux");  ///< The description -- see modinfo
MODULE_VERSION("1.0");            ///< A version number to inform users

////////////////////////////////////////////////////////////////////////////////////////////////

unsigned char entrada[40];
unsigned char saida[20];
static const char hash_alg[] = "sha1";
static struct crypto_shash *hashalg;

static char *key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; 	// variavel para receber chave passada no insmod

static int    majorNumber;                  ///< Stores the device number -- determined automatically
static char   message[256] = {0};           ///< Memory for the string that is passed from userspace
static short  size_of_message;              ///< Used to remember the size of the string stored
static int    numberOpens = 0;              ///< Counts the number of times the device is opened
static struct class*  ebbcharClass  = NULL; ///< The device-driver class struct pointer
static struct device* ebbcharDevice = NULL; ///< The device-driver device struct pointer

// The prototype functions for the character driver -- must come before the struct definition
static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

module_param(key, charp, 0000); 		//para entrada 	

static struct file_operations fops = //Struct para manipular operaçoes de open,read,write,release.
{
   .open = dev_open,
   .read = dev_read,
   .write = dev_write,
   .release = dev_release,
};

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

struct sdesc { //Struct para realizar a operação de hash
    struct shash_desc shash;
    char ctx[];
};

static struct sdesc *init_sdesc(struct crypto_shash *alg) //
{
    struct sdesc *sdesc;
    int size;

    size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
    sdesc = kmalloc(size, GFP_KERNEL);
    if (!sdesc)
        return ERR_PTR(-ENOMEM);
    sdesc->shash.tfm = alg;
    sdesc->shash.flags = 0x0;
    return sdesc;
}

static int calc_hash(const unsigned char *data, unsigned int datalen, unsigned char *digest)
{
	struct sdesc *sdesc; 
	int ret;

	sdesc = init_sdesc(hashalg);
	if (IS_ERR(sdesc)) {
		pr_info("encrypted_key: can't alloc %s\n", hash_alg);
		return PTR_ERR(sdesc);
	}

	ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest); //Envia o sdesc, a string enviada, o tamanho e a operação
	kfree(sdesc);
	return ret;
}

/* Callback function */
static void test_skcipher_cb(struct crypto_async_request *req, int error)
{

    struct tcrypt_result *result = req->data;

    if (error == -EINPROGRESS)
	{
		return;
	}
    result->err = error;
    complete(&result->completion);
    pr_info("Encryption finished successfully\n");
}

/* Perform cipher operation */
static unsigned int test_skcipher_encdec(struct skcipher_def *sk, int enc)
{
	
    int rc = 0;

    if (enc) //Se enc igual a 1 executa a função de criptografia, se igual a 0 executa a função de decriptação
	{
		rc = crypto_skcipher_encrypt(sk->req);
	}
        
    else
	{
		rc = crypto_skcipher_decrypt(sk->req);	
	}

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

//toda vez que é iniciado, ele configura o modulo
static int __init ebbchar_init(void){ 

   printk(KERN_INFO "Inicializando o modulo\n");
   printk(KERN_INFO "A chave definida foi: %s\n", key);

   // Try to dynamically allocate a major number for the device
   majorNumber = register_chrdev(0, DEVICE_NAME, &fops);

   if (majorNumber<0){
      printk(KERN_ALERT "failed to register a major number\n");
      return majorNumber;
   }
   printk(KERN_INFO "Registered correctly with major number %d\n", majorNumber);

   // Register the device class
   ebbcharClass = class_create(THIS_MODULE, CLASS_NAME);

   if (IS_ERR(ebbcharClass)){                // Check for error and clean up if there is
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Failed to register device class\n");
      return PTR_ERR(ebbcharClass);          // Correct way to return an error on a pointer
   }
   printk(KERN_INFO "Device class registered correctly\n");

   // Register the device driver
   ebbcharDevice = device_create(ebbcharClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);

   if (IS_ERR(ebbcharDevice)){               // Clean up if there is an error
      class_destroy(ebbcharClass);           // Repeated code but the alternative is goto statements
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Failed to create the device\n");
      return PTR_ERR(ebbcharDevice);
   }

   printk(KERN_INFO "Device class created correctly\n"); // Made it! device was initialized
   return 0;
}

//é utilizado toda vez que o modulo é removido
static void __exit ebbchar_exit(void){ 

   device_destroy(ebbcharClass, MKDEV(majorNumber, 0));     // remove the device
   class_unregister(ebbcharClass);                          // unregister the device class
   class_destroy(ebbcharClass);                             // remove the device class
   unregister_chrdev(majorNumber, DEVICE_NAME);             // unregister the major number
   printk(KERN_INFO "Ate logo!\n");
}

 //é utilizada toda vez que o device é aberto
static int dev_open(struct inode *inodep, struct file *filep){

   numberOpens++;
   printk(KERN_INFO "\nDevice has been opened %d time(s)\n", numberOpens);
   return 0;
}

// quando o programa utiliza o read, o modulo envia de volta
static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){

   int error_count = 0;
   // copy_to_user returns 0 on success
   error_count = copy_to_user(buffer, message, size_of_message);

   if (error_count==0){            // if true then have success
      printk(KERN_INFO "Mensagem enviada para o usuario\n");
      return (size_of_message=0);  // clear the position to the start and return 0
   }
   else {
      printk(KERN_INFO "A mensagem não foi enviada\n");
      return -EFAULT;              // Failed -- return a bad address message (i.e. -14)
   }
}

//quando o programa da write, o modulo recebe a mensagem enviada
static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){

    struct skcipher_def sk;
    struct crypto_skcipher *skcipher = NULL;
    struct skcipher_request *req = NULL;
    char *scratchpad = NULL;
    char *ivdata = NULL;
    char *bufferaux = kmalloc(16, GFP_KERNEL);;//MARCADO
    char *buffer2 = kmalloc(16, GFP_KERNEL);;//MARCADO
    unsigned char key1[32]; //auxiliar para pegar a chave global
    unsigned char out[160];
    int ret = -EFAULT;
    int i;

    printk("Mensagem recebida, processando...\n");

    skcipher = crypto_alloc_skcipher("ecb(aes)", 0, 0);//define o algoritmo que sera usado
    if (IS_ERR(skcipher)) {
        pr_info("could not allocate skcipher handle\n");
        return PTR_ERR(skcipher);
    }

    req = skcipher_request_alloc(skcipher, GFP_KERNEL); //Tenta realizar uma alocação da requisição feita
    if (!req) {
        pr_info("could not allocate skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }

    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                      test_skcipher_cb,
                      &sk.result);

	strcpy(key1,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); //Atribui valor padrão para a chave
	i=0;
	while(key[i] != '\0')//Atribui o valor da chave global para a local, deixando o que sobrar com \0
	{

		key1[i] = key[i];
		i++; 

	}
	pr_info("KEY UTILZADA %s\n",key1);

    if (crypto_skcipher_setkey(skcipher, key1, 32)) {//seta a key e testa se deu certo
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

    scratchpad = kmalloc(16, GFP_KERNEL);
   	if (!scratchpad) {
        pr_info("could not allocate scratchpad\n");
        goto out;
    }

    sk.tfm = skcipher;
    sk.req = req;

    /* We encrypt one block */
    sg_init_one(&sk.sg, scratchpad, 16); //Linka sk.sg com scratchpad

    sg_copy_to_buffer (&sk.sg, 1, bufferaux, 16); //copia o conteudo de sk.sg para bufferaux
    
    skcipher_request_set_crypt(req, &sk.sg, &sk.sg, 16, ivdata); //tem &
    init_completion(&sk.result.completion);

    sg_copy_to_buffer (&sk.sg, 1, bufferaux, 16);

 
//se for c, deve ser cifrado
//->>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>/* encrypt data */<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<-//
	if(buffer[0] == 'c'){ //buffer possui toda a linha de comando enviada pelo programa de usuario

	char vetaux[18];
	int j;

	for(j=0;j<18;j++)
	{
		vetaux[j] = ' ';
	}
	i=0;
	while(buffer[i] != '\0')
	{

		vetaux[i] = buffer[i];
		i++; 

	}//Preenche vetaux com o valor de buffer e deixa o que sobra com ' '
	
	for(i = 2 ; i < 18;i++){//permite que os 2 primeiros caracteres da mensagem sejam retirados(c,d,h)
		vetaux[i-2]=vetaux[i];
	}
	vetaux[16]='\0';

	strcpy(scratchpad,vetaux);//passa para o scratchpad que sera usado como entrada
	
	printk("Cifrando...\n");
	ret = test_skcipher_encdec(&sk, 1); //funcao que cifra

	sg_copy_to_buffer (&sk.sg, 1, bufferaux, 16);

	bufferaux[16]='\0';
	strcpy(message,bufferaux);  //armazena o resultado
        size_of_message = strlen(message); //message é a variavel que conecta o programa de usuario com o modulo               

    if (ret)
	{
		 goto out;
	}
	
}else if(buffer[0] == 'd'){

//se não, se for d, decifra
//->>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>//DESCRYPT//<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<-//
	
	char vetaux[18];
	strcpy(vetaux,buffer);

	for(i = 2 ; i < 18;i++){//2 primeiros caracteres da mensagem são retirados(c,d,h)
		vetaux[i-2]=vetaux[i];
	}
	vetaux[16]='\0';

	strcpy(scratchpad,vetaux);//passa o vetaux para scratchpad (que é usado como entrada)

	printk("Descifrando...\n");
	ret = test_skcipher_encdec(&sk, 0); //funcao que descifra
	
	sg_copy_to_buffer (&sk.sg, 1, buffer2, 16);
	buffer2[16]='\0';
	
	strcpy(message,buffer2);	
        size_of_message = strlen(message); //message é a variavel que conecta o programa de usuario com o modulo 
	}
	else if(buffer[0] == 'h'){
//se não, se for h, calcula o hash
//->>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>//SHA-1//<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<-//

		hashalg = crypto_alloc_shash(hash_alg, 0, CRYPTO_ALG_ASYNC);

		char vetoraux[42];
		int j;

		for(j=0;j<42;j++)
		{
			vetoraux[j] = ' ';
		}
		i=0;
		while(buffer[i] != '\0')
		{

			vetoraux[i] = buffer[i];
			i++; 

		}

		for(i = 2 ; i < 42;i++){//2 primeiros caracteres da mensagem são retirados
			entrada[i-2]=vetoraux[i];
		}

		entrada[40]='\0';
		printk("entrada: %s\n", entrada);

		calc_hash(entrada, 40, saida);
		crypto_free_shash(hashalg);

		int i;

		printk("calculo do hash...");

		strcpy(message,saida);	
	      size_of_message = strlen(message);
}

    if (ret)
	{
		 goto out;
	}

    *out = 0;
    for (i = 0; i < 512; i++) {
	
        snprintf((char*)out, sizeof(out), "%s 0x%02x", out, scratchpad[i]);
        if ((i % 8)==7) {
           
            *out = 0;
        }
    }
   
out:
	
    if (skcipher)
	{
		crypto_free_skcipher(skcipher);
	}    
    if (req)

	{
		skcipher_request_free(req);
	}

    if (ivdata)

	{
		kfree(ivdata);
	}
       
    if (scratchpad)
	{
	       kfree(scratchpad);
	}

return len;
}

// quando o device é fechado
static int dev_release(struct inode *inodep, struct file *filep){
   printk(KERN_INFO "Device finalizado com sucesso\n\n\n");
   return 0;
}

module_init(ebbchar_init);
module_exit(ebbchar_exit);
