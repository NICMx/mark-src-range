#ifndef SRC_XT_MARKSRCRANGE_H_
#define SRC_XT_MARKSRCRANGE_H_

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
	__u8 sub_prefix_len;
};

__u32 src_to_mark(const struct in6_addr *src,
		const struct xt_marksrcrange_tginfo *cfg);

#endif /* SRC_XT_MARKSRCRANGE_H_ */

