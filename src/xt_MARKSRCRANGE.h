#ifndef _JOOL_COMMON_XT_MARKSRCRANGE_H
#define _JOOL_COMMON_XT_MARKSRCRANGE_H

#include <linux/types.h>
#ifdef __KERNEL__
	#include <linux/in6.h>
#else
	#include <arpa/inet.h>
#endif

struct ipv6_prefix {
	/** IPv6 prefix. The suffix is most of the time assumed to be zero. */
	struct in6_addr address;
	/** Number of bits from "address" which represent the network. */
	__u8 len;
};

struct xt_marksrcrange_tginfo {
	__u32 mark_offset;
	struct ipv6_prefix prefix;
};

#endif /* _JOOL_COMMON_XT_MARKSRCRANGE_H */

