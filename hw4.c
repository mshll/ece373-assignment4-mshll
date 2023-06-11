/*
 * Meshal Almutairi
 * ECE 373
 *
 * Homework 4: Blinking LED
 */
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kdev_t.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/usb.h>

#define DEVCNT 1
#define DEVNAME "ece_led"
#define DEV_CLASS "homework4_class"
#define PCI_DEVICE_ID_INTEL 0x8086
#define PCI_DEVICE_82545EM 0x100F
#define LED_CTRL 0x00E00
#define LED_ON 0xE
#define LED_OFF 0xF

static struct class *homework4_class = NULL;
static struct mydev_dev
{
	struct cdev cdev;
	dev_t mydev_node;
	int syscall_val;
} mydev;

static char *driver_name = "LED_DRIVER";

static const struct pci_device_id pci_tbl[] = {
    {PCI_DEVICE(PCI_DEVICE_ID_INTEL, PCI_DEVICE_82545EM), 0, 0,
     0}, /* Required null terminator */
    {
	0,
    }};

static int blink_rate = 2;
module_param(blink_rate, int, 0);

struct my_pci
{
	struct pci_dev *pdev;
	void *hw_addr;
};
struct my_pci *intel;
struct timer_list blink_timer;

void blink_led(struct timer_list *t)
{
	uint32_t led_val;
	led_val = readl(intel->hw_addr + LED_CTRL);

	// Turn LED on or off
	if (led_val != LED_ON)
	{
		led_val = LED_ON;
		writel(led_val, intel->hw_addr + LED_CTRL);
	}
	else
	{
		led_val = LED_OFF;
		writel(led_val, intel->hw_addr + LED_CTRL);
	}

	mod_timer(&blink_timer, jiffies + (HZ / (blink_rate * 2)));
}

/* function for opening the module */
static int homework4_open(struct inode *inode, struct file *file)
{
	printk(KERN_INFO "Opened " DEVNAME "\n");
	timer_setup(&blink_timer, blink_led, 0);
	mod_timer(&blink_timer, jiffies + (HZ / blink_rate));
	return 0;
}

/* function for reading syscall_val from the module */
static ssize_t homework4_read(struct file *file, char __user *buf, size_t len,
			      loff_t *offset)
{
	int ret, val;
	printk(KERN_INFO "Inside read() system call\n");

	if (*offset >= sizeof(uint32_t))
		return 0;
	if (!buf)
	{
		ret = -EINVAL;
		goto out;
	}

	if (copy_to_user(buf, &val, sizeof(int)))
	{
		ret = -EFAULT;
		goto out;
	}
	ret = sizeof(uint32_t);
	*offset += len;

	printk(KERN_INFO "blink_rate: %d\n", val);

out:
	return ret;
}

/* function for updating syscall_val from what the user inputs */
static ssize_t homework4_write(struct file *file, const char __user *buf,
			       size_t len, loff_t *offset)
{
	int val, ret;

	printk(KERN_INFO "Inside write() system call\n");

	if (!buf)
	{
		ret = -EINVAL;
		goto out;
	}

	if (copy_from_user(&val, buf, len))
	{
		ret = -EFAULT;
		goto mem_out;
	}

	if (val >= 0)
	{
		blink_rate = val;
	}
	else
	{
		ret = -EINVAL;
		goto mem_out;
	}

	ret = len;
	*offset = 0;

mem_out:
out:
	return ret;
}

static int dev_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{

	uint32_t ioremap_len, led_val;
	int err;

	err = pci_enable_device_mem(pdev);
	if (err)
		return err;

	/* set up for high or low dma */
	err = dma_set_mask(&pdev->dev, DMA_BIT_MASK(64));
	if (err)
	{
		dev_err(&pdev->dev, "DMA led_valiguration failed: 0x%x\n", err);
		goto err_dma;
	}

	/* set up pci connections */
	err = pci_request_selected_regions(
	    pdev, pci_select_bars(pdev, IORESOURCE_MEM), driver_name);
	if (err)
	{
		dev_info(&pdev->dev, "pci_request_selected_regions failed %d\n", err);
		goto err_pci_reg;
	}

	pci_set_master(pdev);

	intel = kzalloc(sizeof(*intel), GFP_KERNEL);
	if (!intel)
	{
		err = -ENOMEM;
		goto err_dev_alloc;
	}
	intel->pdev = pdev;
	pci_set_drvdata(pdev, intel);

	/* map device memory */
	ioremap_len = min_t(int, pci_resource_len(pdev, 0), 1024);
	intel->hw_addr = ioremap(pci_resource_start(pdev, 0), ioremap_len);
	if (!intel->hw_addr)
	{
		err = -EIO;
		dev_info(&pdev->dev, "ioremap(0x%04x, 0x%04x) failed: 0x%x\n",
			 (unsigned int)pci_resource_start(pdev, 0),
			 (unsigned int)pci_resource_len(pdev, 0), err);
		goto err_ioremap;
	}

	led_val = readl(intel->hw_addr + LED_CTRL);
	dev_info(&pdev->dev, "led_val = %08x\n", led_val);

	return 0;

err_ioremap:
	kfree(intel);
err_dev_alloc:
	pci_release_selected_regions(pdev, pci_select_bars(pdev, IORESOURCE_MEM));
err_pci_reg:
err_dma:
	pci_disable_device(pdev);
	return err;
}

static void dev_remove(struct pci_dev *pdev)
{
	struct my_pci *intel = pci_get_drvdata(pdev);
	iounmap(intel->hw_addr);
	kfree(intel);
	pci_release_selected_regions(pdev, pci_select_bars(pdev, IORESOURCE_MEM));
	pci_disable_device(pdev);
}

/* struct for directing open, read, and write syscalls */
static struct file_operations mydev_fops = {
    .owner = THIS_MODULE,
    .open = homework4_open,
    .read = homework4_read,
    .write = homework4_write,
};

static struct pci_driver LED_DRIVER = {
    .name = "pci_led",
    .id_table = pci_tbl,
    .probe = dev_probe,
    .remove = dev_remove,
};

/* init function to allocate for the module */
static int __init homework4_init(void)
{
	int ret;
	printk(KERN_INFO "hw4 module loading... blink_rate = %d\n", blink_rate);

	if (alloc_chrdev_region(&mydev.mydev_node, 0, DEVCNT, DEVNAME))
	{
		printk(KERN_ERR "Allocating chrdev failed \n");
		return -1;
	}

	/*initialize the character device */
	cdev_init(&mydev.cdev, &mydev_fops);
	mydev.cdev.owner = THIS_MODULE;

	printk(KERN_INFO "hw4 allocated %d devices at major: %d\n", DEVCNT,
	       MAJOR(mydev.mydev_node));

	homework4_class = class_create(THIS_MODULE, DEV_CLASS);
	device_create(homework4_class, NULL, mydev.mydev_node, NULL, DEVNAME);

	if (cdev_add(&mydev.cdev, mydev.mydev_node, DEVCNT))
	{
		printk(KERN_ERR "cdev_add failed \n");
		/* clean up allocation of chrdev */
		unregister_chrdev_region(mydev.mydev_node, DEVCNT);
		return -1;
	}

	ret = pci_register_driver(&LED_DRIVER);
	return ret;
}

/* exit function to clean up program and extras */
static void __exit homework4_exit(void)
{
	del_timer_sync(&blink_timer);
	cdev_del(&mydev.cdev);
	device_destroy(homework4_class, mydev.mydev_node);
	class_destroy(homework4_class);
	unregister_chrdev_region(mydev.mydev_node, DEVCNT);

	pci_unregister_driver(&LED_DRIVER);
	printk(KERN_INFO "Unloaded module \n");
}

MODULE_DEVICE_TABLE(pci, pci_tbl);
MODULE_AUTHOR("MESHAL ALMUTAIRI");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.2");
module_init(homework4_init);
module_exit(homework4_exit);
