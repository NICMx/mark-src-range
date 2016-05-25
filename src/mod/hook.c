#include <linux/module.h>
#include "target.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva <ydahhrk@gmail.com>");
MODULE_DESCRIPTION("Marks packets depending on source address");
MODULE_ALIAS("ip6t_MARKSRCRANGE");

static struct xt_target marksrcrange_tg_reg __read_mostly = {
	.name           = "MARKSRCRANGE",
	.revision       = 0,
	.family         = NFPROTO_IPV6,
	.hooks          = 1 << NF_INET_PRE_ROUTING,
	.table          = "mangle",
	.checkentry     = check_entry,
	.target         = change_mark,
	.targetsize     = sizeof(struct xt_marksrcrange_tginfo),
	.me             = THIS_MODULE,
};

/**
 * Called when the user modprobes the module.
 * (Which normally happens when they append the first MARKSRCRANGE rule.)
 */
static int __init marksrcrange_tg_init(void)
{
	int error;
	error = xt_register_target(&marksrcrange_tg_reg);
	return (error < 0) ? error : 0;
}

/**
 * Called when the user "modprobe -r"'s the module.
 */
static void __exit marksrcrange_tg_exit(void)
{
	xt_unregister_target(&marksrcrange_tg_reg);
}

module_init(marksrcrange_tg_init);
module_exit(marksrcrange_tg_exit);

