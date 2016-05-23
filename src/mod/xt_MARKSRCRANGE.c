/*
 * Based off the mark match/target. (Linux/net/netfilter/xt_mark.c)
 */

#include "xt_MARKSRCRANGE.h"

#include <linux/module.h>
#include <linux/skbuff.h>
#include <net/ipv6.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva <ydahhrk@gmail.com>");
MODULE_DESCRIPTION("Marks packets depending on source address");
MODULE_ALIAS("ip6t_MARKSRCRANGE");

static bool last_bit_is_zero(unsigned int num)
{
	return !(num & 1);
}

/**
 * The "fourth quadrant" of an IPv6 address is its last 32 bits.
 * (128 / 4 = 32)
 */
static __u32 quadrant4(const struct in6_addr *addr)
{
	return be32_to_cpu(addr->s6_addr32[3]);
}

static int validate_overflow(struct xt_marksrcrange_tginfo *info)
{
	__u64 max_mark;

	/*
	 * This is a special corner case of the validation below.
	 * (1u << 32 is undefined.)
	 */
	if (128 - info->prefix.len == 32) {
		if (info->mark_offset == 0)
			return 0;
		goto overflow;
	}

	max_mark = ((__u64)info->mark_offset)
			+ (1u << (128 - info->prefix.len))
			- 1;
	if (max_mark > 0xFFFFFFFF)
		goto overflow;
	return 0;

overflow:
	pr_err("MARKSRCRANGE: Client count exceeds the amount of marks available.\n");
	pr_err("MARKSRCRANGE: (There are only 2^32 marks)\n");
	return -EINVAL;
}

static int check_entry(const struct xt_tgchk_param *param)
{
	struct ip6t_ip6 *entry = &((struct ip6t_entry *)param->entryinfo)->ipv6;
	struct xt_marksrcrange_tginfo *info = param->targinfo;
	unsigned int quadrant;
	unsigned int i;

	/*
	 * Yes, I'm editing @info. Even though it is pointed by an object that
	 * doesn't want to be modified.
	 *
	 * I need to do this because MARKSRCRANGE depends on --source, but
	 * --source is not available from the target function (so it needs to
	 * be passed in via @info), nor the userspace function where @info is
	 * populated.
	 *
	 * Also, there's at least one in-tree module that also does it:
	 * http://lxr.free-electrons.com/source/net/bridge/netfilter/ebt_nflog.c#L39
	 *
	 * There should also not be any concurrence concerns since the rule
	 * is still being initialized. (And therefore not used.)
	 *
	 * So this might (or might not) be a hack but is definitely not
	 * undefined behavior.
	 */
	memcpy(&info->prefix, &entry->src, sizeof(entry->src));

	/* Assert prefix length >= 96. */
	if (entry->smsk.s6_addr32[0] == 0) {
		pr_err("MARKSRCRANGE: I'm confused. Perhaps you forgot the --source argument?\n");
		return -EINVAL;
	}
	if (entry->smsk.s6_addr32[0] != cpu_to_be32(0xFFFFFFFF))
		goto bad_prefix_len;
	if (entry->smsk.s6_addr32[1] != cpu_to_be32(0xFFFFFFFF))
		goto bad_prefix_len;
	if (entry->smsk.s6_addr32[2] != cpu_to_be32(0xFFFFFFFF))
		goto bad_prefix_len;

	/* Convert subnet mask from dot-decimal to CIDR format. */
	if (entry->smsk.s6_addr32[3] == 0) {
		info->prefix.len = 96;
	} else {
		quadrant = quadrant4(&entry->smsk);
		for (i = 0; last_bit_is_zero(quadrant); i++)
			quadrant >>= 1;
		info->prefix.len = 128 - i;
	}

	return validate_overflow(info);

bad_prefix_len:
	pr_err("MARKSRCRANGE: Prefix length must be >= 96.\n");
	pr_err("MARKSRCRANGE: (There are only 2^32 marks)\n");
	return -EINVAL;
}

static unsigned int change_mark(struct sk_buff *skb,
		const struct xt_action_param *param)
{
	const struct xt_marksrcrange_tginfo *info = param->targinfo;
	struct in6_addr *addr = &ipv6_hdr(skb)->saddr;
	__u32 index;

	index = quadrant4(addr) - quadrant4(&info->prefix.address);
	skb->mark = info->mark_offset + index;
	return XT_CONTINUE;
}

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

static int __init marksrcrange_tg_init(void)
{
	int error;
	error = xt_register_target(&marksrcrange_tg_reg);
	return (error < 0) ? error : 0;
}

static void __exit marksrcrange_tg_exit(void)
{
	xt_unregister_target(&marksrcrange_tg_reg);
}

module_init(marksrcrange_tg_init);
module_exit(marksrcrange_tg_exit);

