#include "target.h"

#include <net/ipv6.h>
#include <linux/skbuff.h>
#include <linux/netfilter_ipv6/ip6_tables.h>

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
		quad = be32_to_cpu(mask->s6_addr32[i]);
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
int check_entry(const struct xt_tgchk_param *param)
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

/**
 * An "IPv6 address quadrant" is one of the address's four 32-bit chunks.
 * This is just a clutter-saver.
 */
static __u32 quadrant(const struct in6_addr *addr, const __u8 bit)
{
	return (bit < 128) ? be32_to_cpu(addr->s6_addr32[bit >> 5]) : 0;
}

static __u32 extract_bits(const struct in6_addr *addr,
		const __u8 from, const __u8 to)
{
	__u32 result;

	/*
	 * Remember: "& 0x1F" is a faster way of saying "% 32"
	 * and ">> 5" is a faster way of saying "/ 32".
	 */

	/* Store the 32 address bits from the quadrant @from is in. */
	result = quadrant(addr, from);
	/* Remove the bits that are at @from's left. */
	result &= (((__u64)0x100000000) >> (from & 0x1F)) - 1;

	/* Do @from and @to belong to different quadrants? */
	if ((from & 0x60) != (to & 0x60)) {
		/* Move the left quadrant bits to make room. */
		result <<= to & 0x1F;
		/* Bring over the relevant bits from @to's quadrant. */
		result |= quadrant(addr, to) >> ((128 - to) & 0x1F);
	} else {
		/* Remove the bits that are at @to's right. */
		result >>= (128 - to) & 0x1F;
	}

	return result;
}

/**
 * This is the meat of the whole project;
 * returns the mark that corresponds to the @src source address,
 * according to the @cfg configuration.
 */
__u32 src_to_mark(const struct in6_addr *src,
		const struct xt_marksrcrange_tginfo *cfg)
{
	return cfg->mark_offset + extract_bits(src, cfg->prefix.len,
			cfg->sub_prefix_len);
}

/**
 * Called on every matched packet; marks the packet depending on its source
 * address.
 */
unsigned int change_mark(struct sk_buff *skb,
		const struct xt_action_param *param)
{
	struct in6_addr *src = &ipv6_hdr(skb)->saddr;

	skb->mark = src_to_mark(src, param->targinfo);
	pr_debug("MARKSRCRANGE: Packet from %pI6c was marked %u.\n",
			src, skb->mark);

	return XT_CONTINUE;
}
