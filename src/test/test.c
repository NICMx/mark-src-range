/*
 * TODO This code is dirty. Lots of stuff was copied from somewhere else;
 * includes might remove a lot of clutter.
 */

#include "xt_MARKSRCRANGE.h"

#include <errno.h>
#include <regex.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <xtables.h>

int str_to_addr6(const char *str, struct in6_addr *result)
{
	if (!inet_pton(AF_INET6, str, result)) {
		printf("Cannot parse '%s' as an IPv6 address.\n", str);
		return 1;
	}
	return 0;
}

int validate_int(const char *str)
{
	regex_t integer_regex;
	int error;

	if (!str) {
		printf("Programming error: 'str' is NULL.\n");
		return 1;
	}

	/* It seems this RE implementation doesn't understand '+'. */
	if (regcomp(&integer_regex, "^[0-9][0-9]*", 0)) {
		printf("Warning: Integer regex didn't compile.\n");
		printf("(I will be unable to validate integer inputs.)\n");
		regfree(&integer_regex);
		/*
		 * Don't punish the user over our incompetence.
		 * If the number is valid, this will not bother the user.
		 * Otherwise strtoull() will just read a random value, but then
		 * the user is at fault.
		 */
		return 0;
	}

	error = regexec(&integer_regex, str, 0, NULL, 0);
	if (error) {
		printf("'%s' is not a number. (error code %d)\n", str, error);
		regfree(&integer_regex);
		return error;
	}

	regfree(&integer_regex);
	return 0;
}

static int str_to_ull(const char *str, char **endptr,
		const unsigned long long int min,
		const unsigned long long int max,
		unsigned long long int *result)
{
	unsigned long long int parsed;
	int error;

	error = validate_int(str);
	if (error)
		return error;

	errno = 0;
	parsed = strtoull(str, endptr, 10);
	if (errno) {
		printf("Parsing of '%s' threw error code %d.\n", str, errno);
		return errno;
	}

	if (parsed < min || max < parsed) {
		printf("'%s' is out of bounds (%llu-%llu).\n", str, min, max);
		return 1;
	}

	*result = parsed;
	return 0;
}

int str_to_u8(const char *str, __u8 *u8_out, __u8 min, __u8 max)
{
	unsigned long long int result;
	int error;

	error = str_to_ull(str, NULL, min, max, &result);

	*u8_out = result;
	return error;
}

int str_to_u32(const char *str, __u32 *u32_out, __u32 min, __u32 max)
{
	unsigned long long int result;
	int error;

	error = str_to_ull(str, NULL, min, max, &result);

	*u32_out = result;
	return error;
}

#define STR_MAX_LEN (INET6_ADDRSTRLEN + 1 + 3) /* [addr + null chara] + / + pref len */
int str_to_prefix6(const char *str, struct ipv6_prefix *prefix_out)
{
	const char *FORMAT = "<IPv6 address>[/<length>] (eg. 64:ff9b::/96)";
	/* strtok corrupts the string, so we'll be using this copy instead. */
	char str_copy[STR_MAX_LEN];
	char *token;
	int error;

	if (strlen(str) + 1 > STR_MAX_LEN) {
		printf("'%s' is too long for this poor, limited parser...\n", str);
		return 1;
	}
	strcpy(str_copy, str);

	token = strtok(str_copy, "/");
	if (!token) {
		printf("Cannot parse '%s' as a %s.\n", str, FORMAT);
		return 1;
	}

	error = str_to_addr6(token, &prefix_out->address);
	if (error)
		return error;

	token = strtok(NULL, "/");
	if (!token) {
		prefix_out->len = 128;
		return 0;
	}
	return str_to_u8(token, &prefix_out->len, 0, 128); /* Error msg already printed. */
}

static int parse_args(int argc, char *argv[], struct xt_marksrcrange_tginfo *info)
{
	unsigned int i;

	memset(info, 0, sizeof(*info));
	info->sub_prefix_len = 128;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--source") == 0) {
			if (str_to_prefix6(argv[i + 1], &info->prefix))
				return 1;
		} else if (strcmp(argv[i], "--mark-offset") == 0) {
			if (str_to_u32(argv[i + 1], &info->mark_offset, 0, 0xFFFFFFFFu))
				return 1;
		} else if (strcmp(argv[i], "--sub-prefix-len") == 0) {
			if (str_to_u8(argv[i + 1], &info->sub_prefix_len, 0, 128))
				return 1;
		}
	}

	if (info->sub_prefix_len - info->prefix.len > 32) {
		printf("Too many addresses! There are only 2^32 marks.\n");
		return 1;
	}

	return 0;
}

void addr6_set_bit(struct in6_addr *addr, unsigned int pos, bool value)
{
	__u32 *quadrant;
	__u32 mask;

	quadrant = &addr->s6_addr32[pos >> 5];
	mask = 1U << (31 - (pos & 0x1FU));

	if (value)
		*quadrant |= htonl(mask);
	else
		*quadrant &= htonl(~mask);
}

static void put_bits(struct in6_addr *addr, __u8 from, __u8 to, __u32 quad)
{
	unsigned int i;
	for (i = from; i <= to; i++) {
		addr6_set_bit(addr, i, quad & (1 << (to - i)));
	}
}

const char *addr6_to_str(const struct in6_addr *addrp)
{
	/* 0000:0000:0000:0000:0000:0000:000.000.000.000
	 * 0000:0000:0000:0000:0000:0000:0000:0000 */
	static char buf[50+1];
	return inet_ntop(AF_INET6, addrp, buf, sizeof(buf));
}

static void print_combinations(struct xt_marksrcrange_tginfo *info)
{
	__u64 mark;
	struct in6_addr addr;
	__u64 iterations;

	memcpy(&addr, &info->prefix.address, sizeof(addr));
	iterations = ((__u64)1) << (info->sub_prefix_len - info->prefix.len);

	printf("Mark		Prefix\n");
	for (mark = 0; mark < iterations; mark++) {
		put_bits(&addr, info->prefix.len, info->sub_prefix_len - 1,
				mark);
		printf("%u	0x%x	%s/%u\n",
				(unsigned int)mark + info->mark_offset,
				(unsigned int)mark + info->mark_offset,
				addr6_to_str(&addr), info->sub_prefix_len);
	}
}

int main(int argc, char *argv[])
{
	struct xt_marksrcrange_tginfo info;
	int error;

	error = parse_args(argc, argv, &info);
	if (error)
		return error;

	print_combinations(&info);
	return 0;
}
