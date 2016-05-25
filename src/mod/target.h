#ifndef SRC_MOD_TARGET_H_
#define SRC_MOD_TARGET_H_

#include <linux/netfilter/x_tables.h>
#include "xt_MARKSRCRANGE.h"

int check_entry(const struct xt_tgchk_param *param);
unsigned int change_mark(struct sk_buff *skb,
		const struct xt_action_param *param);

__u32 src_to_mark(const struct in6_addr *src,
		const struct xt_marksrcrange_tginfo *cfg);

#endif /* SRC_MOD_TARGET_H_ */
