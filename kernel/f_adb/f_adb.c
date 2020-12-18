/*
 * Gadget Driver for Android ADB
 *
 * Copyright (C) 2008 Google, Inc.
 * Author: Mike Lockwood <lockwood@android.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/usb/ch9.h>
#include <linux/delay.h>
#include <linux/usb/gadget.h>
#include <linux/usb/composite.h>
#include <linux/wait.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/types.h>

#include <linux/miscdevice.h>

#undef pr_debug
#define pr_debug(fmt, ...) do {} while (0)


#define ADB_BULK_BUFFER_SIZE           4096

/* number of tx requests to allocate */
#define TX_REQ_MAX 4

static const char adb_shortname[] = "android_adb";

struct adb_dev {
	struct usb_function function;
	struct usb_composite_dev *cdev;
	spinlock_t lock;

	struct usb_ep *ep_in;
	struct usb_ep *ep_out;
	int bulk_out_maxpacket;

	int online;
	int error;

	atomic_t read_excl;
	atomic_t write_excl;
	atomic_t open_excl;

	struct list_head tx_idle;

	wait_queue_head_t read_wq;
	wait_queue_head_t write_wq;
	struct usb_request *rx_req;
	int rx_done;
};

struct f_adb_opts {
	struct usb_function_instance func_inst;
};


static struct usb_interface_descriptor adb_interface_desc = {
	.bLength                = USB_DT_INTERFACE_SIZE,
	.bDescriptorType        = USB_DT_INTERFACE,
	.bInterfaceNumber       = 0,
	.bNumEndpoints          = 2,
	.bInterfaceClass        = 0xFF,
	.bInterfaceSubClass     = 0x42,
	.bInterfaceProtocol     = 1,
};

static struct usb_endpoint_descriptor adb_ss_in_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_IN,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize         = cpu_to_le16(1024),
};

static struct usb_endpoint_descriptor adb_ss_out_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_OUT,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize         = cpu_to_le16(1024),
};

static struct usb_ss_ep_comp_descriptor adb_ss_bulk_comp_desc = {
	.bLength        = sizeof(adb_ss_bulk_comp_desc),
	.bDescriptorType    = USB_DT_SS_ENDPOINT_COMP,

	/* the following 2 values can be tweaked if necessary */
	/* .bMaxBurst =         0, */
	/* .bmAttributes =      0, */
};

static struct usb_endpoint_descriptor adb_hs_in_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_IN,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize         = cpu_to_le16(512),
};

static struct usb_endpoint_descriptor adb_hs_out_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_OUT,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize         = cpu_to_le16(512),
};

static struct usb_endpoint_descriptor adb_fs_in_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_IN,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
};

static struct usb_endpoint_descriptor adb_fs_out_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_OUT,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
};

static struct usb_descriptor_header *fs_adb_function[] = {
	(struct usb_descriptor_header *) &adb_interface_desc,
	(struct usb_descriptor_header *) &adb_fs_in_desc,
	(struct usb_descriptor_header *) &adb_fs_out_desc,
	NULL,
};

static struct usb_descriptor_header *hs_adb_function[] = {
	(struct usb_descriptor_header *) &adb_interface_desc,
	(struct usb_descriptor_header *) &adb_hs_in_desc,
	(struct usb_descriptor_header *) &adb_hs_out_desc,
	NULL,
};

static struct usb_descriptor_header *ss_adb_function[] = {
	(struct usb_descriptor_header *) &adb_interface_desc,
	(struct usb_descriptor_header *) &adb_ss_in_desc,
	(struct usb_descriptor_header *) &adb_ss_bulk_comp_desc,
	(struct usb_descriptor_header *) &adb_ss_out_desc,
	(struct usb_descriptor_header *) &adb_ss_bulk_comp_desc,
	NULL,
};

/* string descriptors: */

static struct usb_string adb_string_defs[] = {
	[0].s = "adb device",
	{  } /* end of list */
};

static struct usb_gadget_strings adb_string_table = {
	.language =     0x0409, /* en-us */
	.strings =      adb_string_defs,
};

static struct usb_gadget_strings *adb_strings[] = {
	&adb_string_table,
	NULL,
};


/* temporary variable used between adb_open() and adb_gadget_bind() */
static struct adb_dev *_adb_dev;

static inline struct adb_dev *func_to_adb(struct usb_function *f)
{
	return container_of(f, struct adb_dev, function);
}


static struct usb_request *adb_request_new(struct usb_ep *ep, int buffer_size)
{
	struct usb_request *req = usb_ep_alloc_request(ep, GFP_KERNEL);

	if (!req)
		return NULL;

	/* now allocate buffers for the requests */
	req->buf = kmalloc(buffer_size, GFP_KERNEL);
	if (!req->buf) {
		usb_ep_free_request(ep, req);
		return NULL;
	}

	return req;
}

static void adb_request_free(struct usb_request *req, struct usb_ep *ep)
{
	if (req) {
		kfree(req->buf);
		usb_ep_free_request(ep, req);
	}
}

static inline int adb_lock(atomic_t *excl)
{
	int ret = 0;

	if (atomic_inc_return(excl) == 1) {
		ret = 0;
	} else {
		atomic_dec(excl);
		ret = -1;
	}

	return ret;
}

static inline void adb_unlock(atomic_t *excl)
{
	atomic_dec(excl);
}

/* add a request to the tail of a list */
void adb_req_put(struct adb_dev *dev, struct list_head *head,
		struct usb_request *req)
{
	unsigned long flags;

	spin_lock_irqsave(&dev->lock, flags);
	list_add_tail(&req->list, head);
	spin_unlock_irqrestore(&dev->lock, flags);
}

/* remove a request from the head of a list */
struct usb_request *adb_req_get(struct adb_dev *dev, struct list_head *head)
{
	unsigned long flags;
	struct usb_request *req;

	spin_lock_irqsave(&dev->lock, flags);
	if (list_empty(head)) {
		req = 0;
	} else {
		req = list_first_entry(head, struct usb_request, list);
		list_del(&req->list);
	}
	spin_unlock_irqrestore(&dev->lock, flags);
	return req;
}

static void adb_complete_in(struct usb_ep *ep, struct usb_request *req)
{
	struct adb_dev *dev = _adb_dev;

	if (req->status != 0)
		dev->error = 1;

	adb_req_put(dev, &dev->tx_idle, req);

	wake_up(&dev->write_wq);
}

static void adb_complete_out(struct usb_ep *ep, struct usb_request *req)
{
	struct adb_dev *dev = _adb_dev;

	dev->rx_done = 1;
	if (req->status != 0 && req->status != -ECONNRESET)
		dev->error = 1;

	wake_up(&dev->read_wq);
}

static int adb_create_bulk_endpoints(struct adb_dev *dev,
				struct usb_endpoint_descriptor *in_desc,
				struct usb_endpoint_descriptor *out_desc)
{
	struct usb_composite_dev *cdev = dev->cdev;
	struct usb_request *req;
	struct usb_ep *ep;
	int i;

	DBG(cdev, "%s dev: %p\n",  __func__, dev);
	ep = usb_ep_autoconfig(cdev->gadget, out_desc);
	if (!ep) {
		DBG(cdev, "usb_ep_autoconfig for ep_out failed\n");
		return -ENODEV;
	}
	DBG(cdev, "usb_ep_autoconfig for adb ep_out got %s\n", ep->name);
	ep->driver_data = dev;      /* claim the endpoint */
	dev->ep_out = ep;

	ep = usb_ep_autoconfig(cdev->gadget, in_desc);
	if (!ep) {
		DBG(cdev, "usb_ep_autoconfig for ep_in failed\n");
		return -ENODEV;
	}
	DBG(cdev, "usb_ep_autoconfig for ep_in got %s\n", ep->name);
	ep->driver_data = dev;      /* claim the endpoint */
	dev->ep_in = ep;

	/* now allocate requests for our endpoints */
	req = adb_request_new(dev->ep_out, ADB_BULK_BUFFER_SIZE);
	if (!req)
		goto fail;
	req->complete = adb_complete_out;
	dev->rx_req = req;

	for (i = 0; i < TX_REQ_MAX; i++) {
		req = adb_request_new(dev->ep_in, ADB_BULK_BUFFER_SIZE);
		if (!req)
			goto fail;
		req->complete = adb_complete_in;
		adb_req_put(dev, &dev->tx_idle, req);
	}

	return 0;

fail:
	pr_err("adb_bind() could not allocate requests\n");
	return -1;
}

static ssize_t adb_read(struct file *fp, char __user *buf,
				size_t count, loff_t *pos)
{
	struct adb_dev *dev = fp->private_data;
	struct usb_request *req;
	int r = count, xfer;
	int ret;

	pr_debug("%s (%d)\n", __func__, count);
	if (!_adb_dev)
		return -ENODEV;

	if (count > ADB_BULK_BUFFER_SIZE)
		return -EINVAL;

	if (adb_lock(&dev->read_excl))
		return -EBUSY;

	/* we will block until we're online */
	while (!(dev->online || dev->error)) {
		pr_debug("%s: waiting for online state\n", __func__);
		ret = wait_event_interruptible(dev->read_wq,
				(dev->online || dev->error));
		if (ret < 0) {
			adb_unlock(&dev->read_excl);
			return ret;
		}
	}
	if (dev->error) {
		r = -EIO;
		goto done;
	}

requeue_req:
	/* queue a request */
	req = dev->rx_req;

	/* buffer size is large enough to accommodate */
	if (count % dev->bulk_out_maxpacket)
		count += (dev->bulk_out_maxpacket -
				(count % dev->bulk_out_maxpacket));
	req->length = count;
	dev->rx_done = 0;
	ret = usb_ep_queue(dev->ep_out, req, GFP_ATOMIC);
	if (ret < 0) {
		pr_debug("%s: failed req %p (%d)\n", __func__, req, ret);
		r = -EIO;
		dev->error = 1;
		goto done;
	} else {
		pr_debug("rx %p queue\n", req);
	}

	/* wait for a request to complete */
	ret = wait_event_interruptible(dev->read_wq, dev->rx_done);
	if (ret < 0) {
		if (ret != -ERESTARTSYS)
			dev->error = 1;
		r = ret;
		usb_ep_dequeue(dev->ep_out, req);
		goto done;
	}
	if (!dev->error) {
		/* If we got a 0-len packet, throw it back and try again. */
		if (req->actual == 0)
			goto requeue_req;

		pr_debug("rx %p %d\n", req, req->actual);
		xfer = (req->actual < count) ? req->actual : count;
		if (copy_to_user(buf, req->buf, xfer))
			r = -EFAULT;

	} else
		r = -EIO;

done:
	adb_unlock(&dev->read_excl);
	pr_debug("%s returning %d\n", __func__, r);
	return r < 0 ? r : xfer;
}

static ssize_t adb_write(struct file *fp, const char __user *buf,
				 size_t count, loff_t *pos)
{
	struct adb_dev *dev = fp->private_data;
	struct usb_request *req = 0;
	int r = count, xfer;
	int ret;

	if (!_adb_dev)
		return -ENODEV;
	pr_debug("%s (%d)\n", __func__, count);

	if (adb_lock(&dev->write_excl))
		return -EBUSY;

	while (count > 0) {
		if (dev->error) {
			pr_debug("%s dev->error\n", __func__);
			r = -EIO;
			break;
		}

		/* get an idle tx request to use */
		req = 0;
		ret = wait_event_interruptible(dev->write_wq,
			(req = adb_req_get(dev, &dev->tx_idle)) || dev->error);

		if (ret < 0) {
			r = ret;
			break;
		}

		if (req != 0) {
			if (count > ADB_BULK_BUFFER_SIZE)
				xfer = ADB_BULK_BUFFER_SIZE;
			else
				xfer = count;
			if (copy_from_user(req->buf, buf, xfer)) {
				r = -EFAULT;
				break;
			}

			req->length = xfer;
			ret = usb_ep_queue(dev->ep_in, req, GFP_ATOMIC);
			if (ret < 0) {
				pr_debug("%s: xfer error %d\n", __func__, ret);
				dev->error = 1;
				r = -EIO;
				break;
			}

			buf += xfer;
			count -= xfer;

			/* zero this so we don't try to free it on error exit */
			req = 0;
		}
	}

	if (req)
		adb_req_put(dev, &dev->tx_idle, req);

	adb_unlock(&dev->write_excl);
	pr_debug("%s returning %d\n", __func__, r);
	return r;
}

static int adb_open(struct inode *ip, struct file *fp)
{
	pr_info("%s\n", __func__);
	if (!_adb_dev)
		return -ENODEV;

	if (adb_lock(&_adb_dev->open_excl))
		return -EBUSY;

	fp->private_data = _adb_dev;

	/* clear the error latch */
	_adb_dev->error = 0;

	return 0;
}

static int adb_release(struct inode *ip, struct file *fp)
{
	pr_info("%s\n", __func__);

	adb_unlock(&_adb_dev->open_excl);
	return 0;
}

/* file operations for ADB device /dev/android_adb */
static const struct file_operations adb_fops = {
	.owner = THIS_MODULE,
	.read = adb_read,
	.write = adb_write,
	.open = adb_open,
	.release = adb_release,
};

static struct miscdevice adb_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = adb_shortname,
	.fops = &adb_fops,
};


static int
adb_function_bind(struct usb_configuration *c, struct usb_function *f)
{
	struct usb_composite_dev *cdev = c->cdev;
	struct adb_dev      *adb = func_to_adb(f);
	int         status;

	adb->cdev = cdev;
	status = -ENODEV;

	if (adb_string_defs[0].id == 0) {
		status = usb_string_id(c->cdev);
		if (status < 0)
			return status;
		adb_string_defs[0].id = status;
	}

	/* allocate instance-specific interface IDs, and patch descriptors */
	status = usb_interface_id(c, f);
	if (status < 0)
		return status;
	adb_interface_desc.bInterfaceNumber = status;

	status = adb_create_bulk_endpoints(adb, &adb_fs_in_desc,
			&adb_fs_out_desc);
	if (status)
		return status;

	/* support high speed hardware */
	if (gadget_is_dualspeed(c->cdev->gadget)) {
		adb_hs_in_desc.bEndpointAddress =
			adb_fs_in_desc.bEndpointAddress;
		adb_hs_out_desc.bEndpointAddress =
			adb_fs_out_desc.bEndpointAddress;
	}

	/* support Super speed hardware */
	if (gadget_is_superspeed(c->cdev->gadget)) {
		adb_ss_in_desc.bEndpointAddress =
			adb_fs_in_desc.bEndpointAddress;
		adb_ss_out_desc.bEndpointAddress =
			adb_fs_out_desc.bEndpointAddress;
	}

	status = usb_assign_descriptors(f, fs_adb_function, hs_adb_function,
			ss_adb_function, NULL);
	if (status)
		goto fail;

	status = misc_register(&adb_device);
	if (status)
		goto fail;

	return 0;

fail:
	ERROR(cdev, "%s: can't bind, err %d\n", f->name, status);
	usb_free_all_descriptors(f);
	return status;

}

static void
adb_function_unbind(struct usb_configuration *c, struct usb_function *f)
{
	struct adb_dev  *dev = func_to_adb(f);
	struct usb_request *req;

	dev->online = 0;
	dev->error = 1;

	wake_up(&dev->read_wq);

	adb_request_free(dev->rx_req, dev->ep_out);
	while ((req = adb_req_get(dev, &dev->tx_idle)))
		adb_request_free(req, dev->ep_in);

	misc_deregister(&adb_device);
	usb_free_all_descriptors(f);
}

static int adb_function_set_alt(struct usb_function *f,
		unsigned int intf, unsigned int alt)
{
	struct adb_dev  *dev = func_to_adb(f);
	struct usb_composite_dev *cdev = f->config->cdev;
	int ret;

	DBG(cdev, "%s intf: %d alt: %d\n", __func__, intf, alt);

	usb_ep_disable(dev->ep_in);

	ret = config_ep_by_speed(cdev->gadget, f, dev->ep_in);
	if (ret)
		return ret;

	ret = usb_ep_enable(dev->ep_in);
	if (ret)
		return ret;

	usb_ep_disable(dev->ep_out);

	ret = config_ep_by_speed(cdev->gadget, f, dev->ep_out);
	if (ret)
		return ret;

	ret = usb_ep_enable(dev->ep_out);
	if (ret) {
		usb_ep_disable(dev->ep_in);
		return ret;
	}

	dev->bulk_out_maxpacket = usb_endpoint_maxp(dev->ep_out->desc);
	dev->online = 1;

	/* readers may be blocked waiting for us to go online */
	wake_up(&dev->read_wq);
	return 0;
}

static void adb_function_disable(struct usb_function *f)
{
	struct adb_dev  *dev = func_to_adb(f);
	struct usb_composite_dev    *cdev = dev->cdev;

	DBG(cdev, "%s cdev %p\n", __func__, cdev);
	dev->online = 0;
	dev->error = 1;
	usb_ep_disable(dev->ep_in);
	usb_ep_disable(dev->ep_out);

	/* readers may be blocked waiting for us to go online */
	wake_up(&dev->read_wq);

}

static void adb_init(struct adb_dev *dev)
{
	spin_lock_init(&dev->lock);

	init_waitqueue_head(&dev->read_wq);
	init_waitqueue_head(&dev->write_wq);

	atomic_set(&dev->open_excl, 0);
	atomic_set(&dev->read_excl, 0);
	atomic_set(&dev->write_excl, 0);

	INIT_LIST_HEAD(&dev->tx_idle);

}

static void adb_free(struct usb_function *f)
{
	struct adb_dev *adb;

	adb = func_to_adb(f);
	kfree(adb);
	_adb_dev = NULL;
}
//function
static struct usb_function *adb_alloc(struct usb_function_instance *fi)
{
	struct adb_dev  *adb;

	/* allocate and initialize one new instance */
	adb = kzalloc(sizeof(*adb), GFP_KERNEL);
	if (!adb)
		return ERR_PTR(-ENOMEM);

	_adb_dev = adb;

	adb_init(adb);

	adb->function.name = "adb";
	adb->function.strings = adb_strings;
	adb->function.bind = adb_function_bind;
	adb->function.unbind = adb_function_unbind;
	adb->function.set_alt = adb_function_set_alt;
	adb->function.disable = adb_function_disable;
	adb->function.free_func = adb_free;

	return &adb->function;
}

//instance
static void adb_free_inst(struct usb_function_instance *f)
{
	struct f_adb_opts *opts;

	opts = container_of(f, struct f_adb_opts, func_inst);
	kfree(opts);
}

static struct usb_function_instance *adb_alloc_inst(void)
{
	struct f_adb_opts *opts;

	opts = kzalloc(sizeof(*opts), GFP_KERNEL);
	if (!opts)
		return ERR_PTR(-ENOMEM);

	opts->func_inst.free_func_inst = adb_free_inst;

	return &opts->func_inst;
}


DECLARE_USB_FUNCTION_INIT(adb, adb_alloc_inst, adb_alloc);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mike Lockwood");
