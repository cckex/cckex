#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>

#include "chardev.h"
#include "net/filter.h"
#include "net/tls_crypto.h"
#include "cc/cchandler.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sven Gebhard");
MODULE_DESCRIPTION("A simple Linux lkm to inject data in covert channels");
MODULE_VERSION("1.0");

static int __init cckex_hook_init(void)
{
	//pr_info("CCKEX-LKM [cckex_hook_init]: HOOK INIT ----------------------");
	cckex_register_filter();
	cckex_register_chardev();

	return 0;
}

static void __exit cckex_hook_exit(void)
{
	//pr_info("CCKEX-LKM [cckex_hook_exit]: HOOK FINI ----------------------");
	cckex_unregister_chardev();
	cckex_unregister_filter();
}

module_init(cckex_hook_init);
module_exit(cckex_hook_exit);
