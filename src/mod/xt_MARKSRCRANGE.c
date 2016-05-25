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

/**
 * An "IPv6 address quadrant" is one of the address's four 32-bit chunks.
 * This is just a clutter-saver.
 */
static __u32 quadrant(const struct in6_addr *addr, unsigned int index)
{
	return ntohl(addr->s6_addr32[index]);
}

static bool last_bit_is_zero(unsigned int num)
{
	return !(num & 1);
}

/**
 * Assumes that @mask represents a network mask and returns its prefix length.
 */
static __u8 dot_decimal_to_cidr(struct in6_addr *mask)
{
	__u32 quad;
	unsigned int i;
	unsigned int j;

	for (i = 0; i < 4; i++) {
		quad = quadrant(mask, i);
		if (quad == 0)
			return 32 * i;
		if (quad != 0xFFFFFFFFu) {
			for (j = 0; last_bit_is_zero(quad); j++)
				quad >>= 1;
			return 32 * (i + 1) - j;
		}
	}

	return 128;
}

static int validate(struct xt_marksrcrange_tginfo *info)
{
	__u64 client_count;
	__u64 max_mark;

	if (info->prefix.len > info->sub_prefix_len) {
		pr_err("MARKSRCRANGE: sub-prefix-len is supposed to be longer or equal than --source's length.\n");
		return -EINVAL;
	}

	if (info->sub_prefix_len - info->prefix.len > 32)
		goto overflow;

	client_count = ((__u64)1) << (info->sub_prefix_len - info->prefix.len);
	max_mark = info->mark_offset + client_count - 1;
	if (max_mark > 0xFFFFFFFFu)
		goto overflow;

	return 0;

overflow:
	pr_err("MARKSRCRANGE: Client count exceeds the amount of marks available.\n");
	pr_err("MARKSRCRANGE: (There are only 2^32 marks)\n");
	return -EINVAL;
}

/**
 * Called when the kernel wants us to validate an entry the user is adding.
 */
static int check_entry(const struct xt_tgchk_param *param)
{
	struct ip6t_ip6 *entry = &((struct ip6t_entry *)param->entryinfo)->ipv6;
	struct xt_marksrcrange_tginfo *info = param->targinfo;

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
	info->prefix.len = dot_decimal_to_cidr(&entry->smsk);

	return validate(info);
}

static __u32 extract_bits(struct in6_addr *addr, __u8 from, __u8 to)
{
	__u32 result;

	/* Store the 32 address bits from the quadrant @from is in. */
	result = quadrant(addr, from >> 5);
	/* Remove the bits that are at @from's left. */
	result &= (((__u64)0x100000000) >> (from & 0x1F)) - 1;

	/* Do @from and @to belong to different quadrants? */
	if ((from & 0x60) != (to & 0x60)) {
		/* Move the bits from the left quadrant to make room. */
		result <<= to & 0x1F;
		/* Bring over the relevant bits from @to's quadrant. */
		result |= quadrant(addr, to >> 5) >> ((128 - to) & 0x1F);
	} else {
		/* Remove the bits that are at @to's right. */
		result >>= (128 - to) & 0x1F;
	}

	return result;
}

/**
 * Called on every matched packet and is the meat of this whole project;
 * marks the packet depending on its source address.
 *
 * Note: Because we're handling prefixes,
 * if --source is 2001:db8::/112 and --sub-prefix-len is 120,
 * 2001:db8::1 will also be marked.
 */
static unsigned int change_mark(struct sk_buff *skb,
		const struct xt_action_param *param)
{
	const struct xt_marksrcrange_tginfo *info = param->targinfo;
	struct in6_addr *src;
	__u32 client;

	src = &ipv6_hdr(skb)->saddr;
	client = extract_bits(src, info->prefix.len, info->sub_prefix_len);
	skb->mark = info->mark_offset + client;

	pr_debug("MARKSRCRANGE: Packet from %pI6c was marked %u.\n",
			src, skb->mark);

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

