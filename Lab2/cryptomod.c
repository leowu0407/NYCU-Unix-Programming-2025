/*
 * Lab problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <linux/module.h>	// included for all kernel modules
#include <linux/kernel.h>	// included for KERN_INFO
#include <linux/init.h>		// included for __init and __exit macros
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/sched.h>	// task_struct requried for current_uid()
#include <linux/cred.h>		// for current_uid();
#include <linux/slab.h>		// for kmalloc/kfree
#include <linux/uaccess.h>	// copy_to_user
#include <linux/string.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include "cryptomod.h"
#include <linux/printk.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/mutex.h>

static DEFINE_MUTEX(cryptomod_mutex);
static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;
static int byte_read;
static int byte_written;
static int frequency_matrix[16][16];
struct private_data {
    char *input_data;
    char *output_data;
    char *plaintext;
    char *ciphertext;
    size_t total_size;
    size_t read_offset;
    size_t process_size;
    size_t total_process_size;
    size_t total_available_size;
    size_t padding_len;
    bool call_finalize;
    bool setup;
    struct CryptoSetup user_setup;
};


static int test_skcipher(u8 *key, size_t key_len, u8 *plaintext, size_t text_len, u8 *ciphertext, bool enc)
{
    struct crypto_skcipher *tfm = NULL;
    struct skcipher_request *req = NULL;
    struct scatterlist sg;
    DECLARE_CRYPTO_WAIT(wait);
    int err;

    if (text_len % 16 != 0) {
        pr_err("Input data length must be a multiple of 16\n");
        return -EINVAL;
    }
    /*
     * Allocate a tfm (a transformation object) and set the key.
     *
     * In real-world use, a tfm and key are typically used for many
     * encryption/decryption operations.  But in this example, we'll just do a
     * single encryption operation with it (which is not very efficient).
     */

    tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
    if (IS_ERR(tfm)) {
            pr_err("Error allocating ecb(aes) handle: %ld\n", PTR_ERR(tfm));
            return PTR_ERR(tfm);
    }

    err = crypto_skcipher_setkey(tfm, key, key_len);
    if (err) {
            pr_err("Error setting key: %d\n", err);
            goto out;
    }

    /* Allocate a request object */
    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
            err = -ENOMEM;
            goto out;
    }

    /*
     * Encrypt the data in-place.
     *
     * For simplicity, in this example we wait for the request to complete
     * before proceeding, even if the underlying implementation is asynchronous.
     *
     * To decrypt instead of encrypt, just change crypto_skcipher_encrypt() to
     * crypto_skcipher_decrypt().
     */
    /* you also can init two scatterlists instead of inplace operation */
    sg_init_one(&sg, plaintext, text_len); // You need to make sure that data size is mutiple of block size
    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                                       CRYPTO_TFM_REQ_MAY_SLEEP,
                                  crypto_req_done, &wait);
    skcipher_request_set_crypt(req, &sg, &sg, text_len, NULL);
    if (enc){
        err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
        if (err) {
            pr_err("Error encrypting data: %d\n", err);
            goto out;
        }
    }
    else {
        err = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
        if (err) {
            pr_err("Error encrypting data: %d\n", err);
            goto out;
        }
    }

    memcpy(ciphertext, sg_virt(&sg), text_len);

    pr_debug("Encryption was successful\n");
out:
    crypto_free_skcipher(tfm);
    skcipher_request_free(req);
    return err;
}

static int cryptomod_dev_open(struct inode *i, struct file *f) {
	struct private_data *priv;
	priv = kzalloc(sizeof(struct private_data), GFP_KERNEL);
	priv->input_data = kmalloc(131072, GFP_KERNEL);
	priv->output_data = kmalloc(131072, GFP_KERNEL);
	priv->plaintext = kmalloc(131072, GFP_KERNEL);
	priv->ciphertext = kmalloc(131072, GFP_KERNEL);
	priv->total_size = 0;
	priv->read_offset = 0;
	priv->total_process_size = 0;
	priv->total_available_size = 0;
	priv->call_finalize = false;
	priv->setup = false;
	f->private_data = priv;
	printk(KERN_INFO "cryptomod: device opened.\n");
	return 0;
}

static int cryptomod_dev_close(struct inode *i, struct file *f) {
	struct private_data *priv = f->private_data;
	printk(KERN_INFO "cryptomod: device closed.\n");
	kfree(priv->input_data);
        kfree(priv->output_data);
        kfree(priv->plaintext);
        kfree(priv->ciphertext);
	kfree(priv);
	return 0;
}

static ssize_t cryptomod_dev_read(struct file *f, char __user *buf, size_t len, loff_t *off) {
	struct private_data *priv = f->private_data;
	if ((priv->user_setup.io_mode == 0) && (priv->call_finalize == false)) {
	    return -EINVAL;
	}
	
	// advance mode
	if (priv->user_setup.io_mode == 1) {
	    len = (len / 16) * 16;
	    if (len > priv->total_available_size) {
	        len = (priv->total_available_size / 16) * 16;
	    }

	    if (copy_to_user(buf, priv->output_data, len)) {
                return -EBUSY;
            }
	    priv->total_available_size -= len;
	    if (priv->user_setup.c_mode == 0) {
		mutex_lock(&cryptomod_mutex);
                for (size_t i = 0; i < len; i++) {
                    unsigned char byte = priv->output_data[i];
                    int row = byte / 16;
                    int col = byte % 16;
                    frequency_matrix[row][col]++;
                }

            }
	    memmove(priv->output_data, priv->output_data + len, priv->total_available_size);
	    byte_read += len;
	    mutex_unlock(&cryptomod_mutex);
	}
	else { // basic mode
	    if (priv->total_size == 0) {
                if (priv->call_finalize) {
                    return 0;
                }
                return -EAGAIN;
            }
	    if (len > priv->total_size) {
                len = priv->total_size;
            }
            if (copy_to_user(buf, priv->output_data + priv->read_offset, len)) {
                return -EBUSY;
            }
            if (priv->user_setup.c_mode == 0) {
		mutex_lock(&cryptomod_mutex);
                for (size_t i = 0; i < len; i++) {
                    unsigned char byte = priv->output_data[priv->read_offset + i];
                    int row = byte / 16;
                    int col = byte % 16;
                    frequency_matrix[row][col]++;
                }
            }
            priv->read_offset += len;
            byte_read += len;
            priv->total_size -= len;
	    mutex_unlock(&cryptomod_mutex);    
	}
	
	printk(KERN_INFO "cryptomod: read %zu bytes @ %llu.\n", len, *off);
	return len;
}

static ssize_t cryptomod_dev_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
        struct private_data *priv = f->private_data;	
	if (priv->call_finalize | !priv->setup) {
	    return -EINVAL;
	}
	// advance mode
	if (priv->user_setup.io_mode == 1) {
	    if (copy_from_user(priv->input_data + priv->total_size, buf, len)) {
                return -EBUSY;
            }
	    priv->total_size += len;
	    if (priv->user_setup.c_mode == 1){
		if (priv->total_size % 16) {
		    priv->process_size = (priv->total_size / 16) * 16;
		}
		else {
		    priv->process_size = ((priv->total_size-16) / 16) * 16;
		}
	    }
	    else {
	        priv->process_size = (priv->total_size / 16) * 16;
	    }
            if (priv->process_size > 0) {
		memcpy(priv->plaintext, priv->input_data, priv->process_size);
                memmove(priv->input_data, priv->input_data + priv->process_size, priv->total_size - priv->process_size);
		if (priv->user_setup.c_mode == 0) {
		    test_skcipher(priv->user_setup.key, priv->user_setup.key_len, priv->plaintext, priv->process_size, priv->ciphertext, true);
		    printk(KERN_INFO "encrypt %zu bytes\n", priv->process_size);
		}
		else {
		    test_skcipher(priv->user_setup.key, priv->user_setup.key_len, priv->plaintext, priv->process_size, priv->ciphertext, false);
                    printk(KERN_INFO "decrypt %zu bytes\n", priv->process_size);
		}
		memcpy(priv->output_data + priv->total_available_size, priv->ciphertext, priv->process_size);
                priv->total_process_size += priv->process_size;
		priv->total_size -= priv->process_size;
                priv->total_available_size += priv->process_size;
            }
	    mutex_lock(&cryptomod_mutex);
            byte_written += len;
	    mutex_unlock(&cryptomod_mutex);
	}
	else {
     	    if (copy_from_user(priv->input_data + priv->total_size, buf, len)) {
	        return -EBUSY;
	    }
	    priv->total_size += len;
	    mutex_lock(&cryptomod_mutex);
	    byte_written += len;
	    mutex_unlock(&cryptomod_mutex);
	}

	printk(KERN_INFO "cryptomod: write %zu bytes @ %llu.\n", len, *off);
	return len;
}

static long cryptomod_dev_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    struct private_data *priv = f->private_data;
    printk(KERN_INFO "cryptomod: ioctl cmd=%u arg=%lu.\n", cmd, arg);

    switch (cmd) {
    	case CM_IOC_SETUP:
	    if (copy_from_user(&priv->user_setup, (struct CryptoSetup __user *)arg, sizeof(struct CryptoSetup))) {
                return -EINVAL;
            }
            
            if (priv->user_setup.key_len != 16 && priv->user_setup.key_len != 24 && priv->user_setup.key_len != 32) {
                return -EINVAL;
            }
	    if (((priv->user_setup.c_mode != 0) && (priv->user_setup.c_mode != 1)) || ((priv->user_setup.io_mode != 0) && (priv->user_setup.io_mode != 1))) {
	        return -EINVAL;
	    }
            priv->setup = true; 
            printk(KERN_INFO "Configure CryptoSetup successfully\n");

	    break;

	case CM_IOC_FINALIZE:
	    if (!priv->setup) {
	        return -EINVAL;
	    }
	    priv->call_finalize = true;
	    // basic mode
	    if (priv->user_setup.io_mode == 0) {
	        if (priv->user_setup.c_mode == 0) {
	            priv->padding_len = 16 - (priv->total_size % 16);
		    memset(priv->input_data + priv->total_size, priv->padding_len, priv->padding_len);
		    priv->total_size += priv->padding_len;
		    test_skcipher(priv->user_setup.key, priv->user_setup.key_len, priv->input_data, priv->total_size, priv->output_data, true);
	        }
	        else {
		    if (priv->total_size % 16) {
		    	return -EINVAL;
		    }
	    	    test_skcipher(priv->user_setup.key, priv->user_setup.key_len, priv->input_data, priv->total_size, priv->output_data, false);
                    priv->padding_len = priv->output_data[priv->total_size - 1];
		    if (priv->padding_len < 1 || priv->padding_len > 16) {
			return -EINVAL;
	            }
                    priv->total_size -= priv->padding_len;
		    memset(priv->output_data + priv->total_size, 0, priv->padding_len);
	        }
            }
	    else {  // advance mode
		if (priv->user_setup.c_mode == 0) {
                    priv->padding_len = 16 - (priv->total_size % 16);
                    memset(priv->input_data + priv->total_size, priv->padding_len, priv->padding_len);
                    priv->total_size += priv->padding_len;
		    memcpy(priv->plaintext, priv->input_data, 16);
                    test_skcipher(priv->user_setup.key, priv->user_setup.key_len, priv->plaintext, priv->total_size, priv->ciphertext, true);
		    memcpy(priv->output_data + priv->total_available_size, priv->ciphertext, 16);
		    priv->total_available_size += 16;
                }
                else {
		    if (priv->total_size % 16) {
                        return -EINVAL;
                    }
		    memcpy(priv->plaintext, priv->input_data, 16);
                    test_skcipher(priv->user_setup.key, priv->user_setup.key_len, priv->plaintext, priv->total_size, priv->ciphertext, false);
		    priv->padding_len = priv->ciphertext[15];
		    if (priv->padding_len < 1 || priv->padding_len > 16) {
                        return -EINVAL;
                    }
		    memset(priv->ciphertext+16-priv->padding_len, 0, priv->padding_len);
		    memcpy(priv->output_data + priv->total_available_size, priv->ciphertext, 16 - priv->padding_len);
                    priv->total_available_size += (16-priv->padding_len);
		}
	         
	    }
	    printk(KERN_INFO "FINALIZE\n");
	    break;
	
	case CM_IOC_CLEANUP:
	    printk(KERN_INFO "CLEANUP\n");
            priv->call_finalize = false;
	    kfree(priv->input_data);
	    kfree(priv->output_data);
	    kfree(priv->plaintext);
	    kfree(priv->ciphertext);
	    break;

	case CM_IOC_CNT_RST:
	    byte_read = 0;
	    byte_written = 0;
	    memset(frequency_matrix, 0 , sizeof(frequency_matrix));
	    break;
	    
	default:
	    return -EINVAL;
    }
    return 0;
}

static const struct file_operations cryptomod_dev_fops = {
	.owner = THIS_MODULE,
	.open = cryptomod_dev_open,
	.read = cryptomod_dev_read,
	.write = cryptomod_dev_write,
	.unlocked_ioctl = cryptomod_dev_ioctl,
	.release = cryptomod_dev_close
};

static int cryptomod_proc_read(struct seq_file *m, void *v) {
	seq_printf(m, "%d %d\n", byte_read, byte_written);

        for (int i = 0; i < 16; i++) {
            for (int j = 0; j < 16; j++) {
                seq_printf(m, "%d ", frequency_matrix[i][j]);
            }
            seq_printf(m, "\n");
        }
	return 0;
}

static int cryptomod_proc_open(struct inode *inode, struct file *file) {
	return single_open(file, cryptomod_proc_read, NULL);
}

static const struct proc_ops cryptomod_proc_fops = {
	.proc_open = cryptomod_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static char *cryptomod_devnode(const struct device *dev, umode_t *mode) {
	if(mode == NULL) return NULL;
	*mode = 0666;
	return NULL;
}

static int __init cryptomod_init(void)
{
	// create char dev
	if(alloc_chrdev_region(&devnum, 0, 1, "updev") < 0)
		return -1;
	if((clazz = class_create("upclass")) == NULL)
		goto release_region;
	clazz->devnode = cryptomod_devnode;
	if(device_create(clazz, NULL, devnum, NULL, "cryptodev") == NULL)
		goto release_class;
	cdev_init(&c_dev, &cryptomod_dev_fops);
	if(cdev_add(&c_dev, devnum, 1) == -1)
		goto release_device;

	// create proc
	proc_create("cryptomod", 0, NULL, &cryptomod_proc_fops);

	printk(KERN_INFO "cryptomod: initialized.\n");
	return 0;    // Non-zero return means that the module couldn't be loaded.

release_device:
	device_destroy(clazz, devnum);
release_class:
	class_destroy(clazz);
release_region:
	unregister_chrdev_region(devnum, 1);
	return -1;
}

static void __exit cryptomod_cleanup(void)
{
	remove_proc_entry("cryptomod", NULL);

	cdev_del(&c_dev);
	device_destroy(clazz, devnum);
	class_destroy(clazz);
	unregister_chrdev_region(devnum, 1);

	printk(KERN_INFO "cryptomod: cleaned up.\n");
}

module_init(cryptomod_init);
module_exit(cryptomod_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chun-Ying Huang");
MODULE_DESCRIPTION("The unix programming course demo kernel module.");
