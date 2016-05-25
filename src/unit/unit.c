#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/inet.h>
#include "xt_MARKSRCRANGE.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva <ydahhrk@gmail.com>");
MODULE_DESCRIPTION("Unit tests for xt_MARKSRCRANGE");

static unsigned int yays = 0;
static unsigned int nays = 0;

/**
 * Asserts src_to_mark(@src_str, @plen, @splen, @offset) == @expected.
 */
static bool test(char *src_str, __u8 plen, __u8 splen, __u32 offset,
		__u32 expected)
{
	struct in6_addr src;
	struct xt_marksrcrange_tginfo cfg;
	__u32 actual;

	if (!in6_pton(src_str, -1, (u8 *) &src, '\0', NULL)) {
		pr_err("'%s' does not seem to be a v6 address.\n", src_str);
		nays++;
		return false;
	}
	/* The algorithm does not depend on this, so whatever it. */
	memset(&cfg.prefix.address, 0, sizeof(cfg.prefix.address));
	cfg.prefix.len = plen;
	cfg.mark_offset = offset;
	cfg.sub_prefix_len = splen;

	actual = src_to_mark(&src, &cfg);
	if (actual != expected) {
		pr_err("Test #%u failed: Expected %u (0x%x), got %u (0x%x).\n",
				yays + nays, expected, expected,
				actual, actual);
		nays++;
		return false;
	}

	yays++;
	return true;
}

static int msr_init(void)
{
	const char *MANY_FS = "ffff:ffff:ffff:ffff:ffff:ffff";
	bool success = true;
	pr_info("Starting xt_MARKSRCRANGE tests.\n");

	/*
	 * Simplest possible: Last quadrant only, boring config, client bytes
	 * glued to address boundaries, client bytes all zero.
	 */
	success &= test("::", 96, 128, 0, 0);
	success &= test("::", 112, 128, 0, 0);
	success &= test("::", 120, 128, 0, 0);
	success &= test("::", 125, 128, 0, 0);
	success &= test("::", 127, 128, 0, 0);
	success &= test("::", 128, 128, 0, 0);

	/*
	 * Same, but invert bytes to make sure it's not an initialization trick.
	 */
	success &= test(MANY_FS "::", 96, 128, 0, 0);
	success &= test(MANY_FS ":ffff::", 112, 128, 0, 0);
	success &= test(MANY_FS ":ffff:ff00", 120, 128, 0, 0);
	success &= test(MANY_FS ":ffff:fff8", 125, 128, 0, 0);
	success &= test(MANY_FS ":ffff:fffe", 127, 128, 0, 0);
	success &= test(MANY_FS ":ffff:ffff", 128, 128, 0, 0);

	/*
	 * Now do everything again, except try the last address of the range.
	 */
	success &= test("::ffff:ffff", 96, 128, 0, 0xffffffff);
	success &= test("::ffff", 112, 128, 0, 0xffff);
	success &= test("::ff", 120, 128, 0, 0xff);
	success &= test("::7", 125, 128, 0, 7);
	success &= test("::1", 127, 128, 0, 1);
	success &= test(MANY_FS ":ffff:ffff", 96, 128, 0, 0xffffffff);
	success &= test(MANY_FS ":ffff:ffff", 112, 128, 0, 0xffff);
	success &= test(MANY_FS ":ffff:ffff", 120, 128, 0, 0xff);
	success &= test(MANY_FS ":ffff:ffff", 125, 128, 0, 7);
	success &= test(MANY_FS ":ffff:ffff", 127, 128, 0, 1);
	success &= test(MANY_FS ":ffff:ffff", 128, 128, 0, 0);

	/*
	 * Now do everything yet again, except try some other quadrant.
	 */
	success &= test("::", 8, 32, 0, 0);
	success &= test("::", 16, 32, 0, 0);
	success &= test("::", 20, 32, 0, 0);
	success &= test("::", 29, 32, 0, 0);
	success &= test("::", 31, 32, 0, 0);
	success &= test("::", 32, 32, 0, 0);
	success &= test("ffff:ffff::", 0, 32, 0, 0xffffffff);
	success &= test("0000:ffff::", 16, 32, 0, 0xffff);
	success &= test("0000:00ff::", 20, 32, 0, 0xff);
	success &= test("0000:0007::", 29, 32, 0, 7);
	success &= test("0000:0001::", 31, 32, 0, 1);

	/*
	 * Now try 8-bit ranges, aligned to byte boundaries.
	 */
	success &= test("fb00::", 0, 8, 0, 0xfb);
	success &= test("0:0:2000::", 32, 40, 0, 0x20);
	success &= test("0:0:0050::", 40, 48, 0, 0x50);
	success &= test("0:0:0050::", 40, 48, 0, 0x50);
	success &= test("0:0:0:fa00::", 48, 56, 0, 0xfa);
	success &= test("0:0:0:0012::", 56, 64, 0, 0x12);
	success &= test("0:0:0:0:3400::", 64, 72, 0, 0x34);
	success &= test("0:0:0:0:0078::", 72, 80, 0, 0x78);
	success &= test("0:0:0:0:0:9a00::", 80, 88, 0, 0x9a);
	success &= test("0:0:0:0:0:00bc::", 88, 96, 0, 0xbc);
	success &= test("::4c", 120, 128, 0, 0x4c);

	/*
	 * Now try unaligned 8-bit ranges.
	 */
	success &= test("0ba0::", 4, 12, 0, 0xba);
	success &= test("03a8::", 6, 14, 0, 0xea);
	success &= test("a:c000::", 12, 20, 0, 0xac);
	success &= test("5:6000::", 13, 21, 0, 0xac);
	success &= test("0:3:4000::", 28, 36, 0, 0x34);
	success &= test("0:0:0120::", 35, 43, 0, 0x09);
	success &= test("0:0:0:0:0:2c40::", 82, 90, 0, 0xb1);
	success &= test("::1:7000:0", 94, 102, 0, 0x5c);
	success &= test("::a:6000", 107, 115, 0, 0x53);

	/*
	 * Now try unaligned random-sized stuff with a little bit of offset
	 * for good measure.
	 */
	success &= test("0123:4560::", 4, 28, 0, 0x123456);
	success &= test("0:0:0053:0a00::", 40, 55, 0, 0x2985);
	success &= test("0:0:0:0:0001:2300::", 79, 89, 0, 0x246);
	success &= test("::3458:abcc", 98, 127, 0, 0x1a2c55e6);
	success &= test("0000:0427:ab21:8000::", 21, 50, 0, 0x109eac86);
	success &= test("0:0:0:0066:bb00::", 57, 79, 0, 0x335d80);
	success &= test("::0047:9b00:0000", 83, 121, 1, 0x8f360001);

	pr_info("Done. %u tests, %u errors.\n", yays + nays, nays);
	return success ? 0 : -EINVAL;
}

static void msr_exit(void)
{
	/* No code. */
}

module_init(msr_init);
module_exit(msr_exit);
