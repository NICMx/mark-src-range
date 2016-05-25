#include "xt_MARKSRCRANGE.h"

#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <xtables.h>

static const struct option opts[] = {
	{ .name = "mark-offset", .has_arg = 1, .val = 'm' },
	{ .name = "sub-prefix-len", .has_arg = 1, .val = 's' },
	{ NULL },
};

/**
 * Called whenever the user runs `ip6tables -j MARKSRCRANGE -h`.
 */
static void marksrcrange_tg_help(void)
{
	printf("MARKSRCRANGE target options:\n");
	printf("[!] --mark-offset               Number from which to start assigning marks\n");
	printf("[!] --sub-prefix-len            See https://github.com/NICMx/mark-src-range/issues/1\n");
}

/**
 * Called first whenever the user appends a MARKSRCRANGE rule to mangle.
 */
static void marksrcrange_tg_init(struct xt_entry_target *target)
{
	struct xt_marksrcrange_tginfo *info = (void *)target->data;
	memset(info, 0, sizeof(*info));
	info->sub_prefix_len = 128;
}

bool parse_mark_offset(char *argv, __u32 *result)
{
	unsigned int tmp;

	if (xtables_strtoui(argv, NULL, &tmp, 0, 0xFFFFFFFFu)) {
		*result = tmp;
		return true;
	}

	xtables_error(PARAMETER_PROBLEM,
			"Cannot parse '%s' as an unsigned 32-bit integer.",
			argv);
	return false;
}

bool parse_prefix_len(char *argv, __u8 *result)
{
	unsigned int tmp;

	if (xtables_strtoui(argv, NULL, &tmp, 0, 128)) {
		*result = tmp;
		return true;
	}

	xtables_error(PARAMETER_PROBLEM,
			"Cannot parse '%s' as an integer in the range [0, 128].",
			argv);
	return false;
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

	switch (c) {
	case 'm':
		return parse_mark_offset(optarg, &info->mark_offset);
	case 's':
		return parse_prefix_len(optarg, &info->sub_prefix_len);
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

	max = (((__u64)1) << (info->sub_prefix_len - info->prefix.len)) - 1;

	printf("marks %u-%u (0x%x-0x%x) /%u/%u ",
			info->mark_offset, info->mark_offset + max,
			info->mark_offset, info->mark_offset + max,
			info->prefix.len, info->sub_prefix_len);
}

/**
 * Called whenever the user runs `ip6tables-save`.
 * (Remember you might need to sudo.)
 */
static void marksrcrange_tg_save(const void *entry,
		const struct xt_entry_target *target)
{
	const struct xt_marksrcrange_tginfo *info = (const void *)target->data;
	printf(" --mark-offset %u --sub-prefix-len %u",
			info->mark_offset,
			info->sub_prefix_len);
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

