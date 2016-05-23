#include "xt_MARKSRCRANGE.h"

#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <xtables.h>

static const struct option opts[] = {
	{ .name = "mark-offset", .has_arg = 1, .val = 'm' },
	{ NULL },
};

/**
 * Called whenever the user runs `ip6tables -j MARKSRCRANGE -h`.
 */
static void marksrcrange_tg_help(void)
{
	printf("MARKSRCRANGE target options:\n");
	printf("[!] --mark-offset               Number from which to start assigning marks\n");
}

/**
 * Called first whenever the user appends a MARKSRCRANGE rule to mangle.
 */
static void marksrcrange_tg_init(struct xt_entry_target *target)
{
	struct xt_marksrcrange_tginfo *info = (void *)target->data;
	memset(info, 0, sizeof(*info));
}

/**
 * Called after _tg_init once for every argument the ip6tables command bridges
 * to us.
 */
static int marksrcrange_tg_parse(int c, char **argv, int invert,
		unsigned int *flags, const void *entry,
		struct xt_entry_target **target)
{
	struct xt_marksrcrange_tginfo *info = (void *)(*target)->data;
	unsigned int tmp;

	switch (c) {
	case 'm':
		if (!xtables_strtoui(optarg, NULL, &tmp, 0, 0xFFFFFFFFu)) {
			xtables_error(PARAMETER_PROBLEM,
					"Cannot parse '%s' as an unsigned 32-bit integer.",
					optarg);
			return false;
		}

		info->mark_offset = tmp;
		return true;
	}

	return false;
}

/**
 * Called whenever the user runs `ip6tables -t mangle -L`.
 */
static void marksrcrange_tg_print(const void *entry,
		const struct xt_entry_target *target,
		int numeric)
{
	const struct xt_marksrcrange_tginfo *info = (const void *)target->data;
	unsigned int max;
	struct in6_addr last;

	if (info->prefix.len != 96)
		max = (1u << (128 - info->prefix.len)) - 1;
	else
		max = 0xFFFFFFFF;
	last = info->prefix.address;
	last.s6_addr32[3] = htonl(ntohl(last.s6_addr32[3]) | max);

	printf("marks %u-%u (0x%x-0x%x); addresses %s - ",
			info->mark_offset, info->mark_offset + max,
			info->mark_offset, info->mark_offset + max,
			xtables_ip6addr_to_numeric(&info->prefix.address));
	/*
	 * xtables_ip6addr_to_numeric's return value is static so this needs to
	 * be a separate printf...
	 * Beautiful.
	 */
	printf("%s ", xtables_ip6addr_to_numeric(&last));
}

/**
 * Called whenever the user runs `ip6tables-save`.
 * (Remember you might need to sudo.)
 */
static void marksrcrange_tg_save(const void *entry,
		const struct xt_entry_target *target)
{
	const struct xt_marksrcrange_tginfo *info = (const void *)target->data;
	printf(" --mark-offset %u", info->mark_offset);
}

static struct xtables_target marksrcrange_tg_reg = {
	.version       = XTABLES_VERSION,
	.name          = "MARKSRCRANGE",
	.revision      = 0,
	.family        = PF_INET6,
	.size          = XT_ALIGN(sizeof(struct xt_marksrcrange_tginfo)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_marksrcrange_tginfo)),
	.help          = marksrcrange_tg_help,
	.init          = marksrcrange_tg_init,
	.parse         = marksrcrange_tg_parse,
	.print         = marksrcrange_tg_print,
	.save          = marksrcrange_tg_save,
	.extra_opts    = opts,
};

/**
 * I'm not sure exactly when this is called, but is pretty much the `main()` of
 * this program.
 */
static void _init(void)
{
	xtables_register_target(&marksrcrange_tg_reg);
}

