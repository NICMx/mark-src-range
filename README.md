# MARKSRCRANGE ip6tables target

## Introduction

We learned in [Jool issue #214](https://github.com/NICMx/Jool/issues/214) that ip6tables can be a bit of a bottleneck when it's heavily populated.

I also conjecture that most ip6tables configurations will look somewhat like this when paired with Jool:

	ip6tables -t mangle -A PREROUTING --source 2001:db8::1 -j MARK --set-mark 1
	ip6tables -t mangle -A PREROUTING --source 2001:db8::2 -j MARK --set-mark 2
	ip6tables -t mangle -A PREROUTING --source 2001:db8::3 -j MARK --set-mark 3
	...
	ip6tables -t mangle -A PREROUTING --source 2001:db8::<N> -j MARK --set-mark <N>

`MARKSRCRANGE` is an ip6tables plugin target that condenses, and therefore optimizes, this configuration.

For example, this:

	ip6tables -t mangle -A PREROUTING --source 2001:db8::/120 -j MARKSRCRANGE

Is equivalent to this:

	ip6tables -t mangle -A PREROUTING --source 2001:db8::0 -j MARK --set-mark 0
	ip6tables -t mangle -A PREROUTING --source 2001:db8::1 -j MARK --set-mark 1
	ip6tables -t mangle -A PREROUTING --source 2001:db8::2 -j MARK --set-mark 2
	...
	ip6tables -t mangle -A PREROUTING --source 2001:db8::FF -j MARK --set-mark 255

And this:

	ip6tables -t mangle -A PREROUTING --source 2001:db8:0:a00::/56 -j MARKSRCRANGE --mark-offset 0 --sub-prefix-len 64
	ip6tables -t mangle -A PREROUTING --source 2001:db8:0:b00::/56 -j MARKSRCRANGE --mark-offset 256 --sub-prefix-len 64

Is the same as this:

	ip6tables -t mangle -A PREROUTING --source 2001:db8:0:a00::/64 -j MARK --set-mark 0
	ip6tables -t mangle -A PREROUTING --source 2001:db8:0:a01::/64 -j MARK --set-mark 1
	...
	ip6tables -t mangle -A PREROUTING --source 2001:db8:0:aff::/64 -j MARK --set-mark 255

	ip6tables -t mangle -A PREROUTING --source 2001:db8:0:b00::/64 -j MARK --set-mark 256
	ip6tables -t mangle -A PREROUTING --source 2001:db8:0:b01::/64 -j MARK --set-mark 257
	...
	ip6tables -t mangle -A PREROUTING --source 2001:db8:0:bff::/64 -j MARK --set-mark 511

## Installation

Kbuild only and no configuration script yet; sorry.

	# apt-get install iptables-dev
	$ cd src
	$ make
	# make install

## Usage

	ip6tables -t mangle -A PREROUTING --source <PREFIX> -j MARKSRCRANGE [--mark-offset <OFFSET>] [--sub-prefix-len <SUB>]

Will distribute longer sub-prefixes of length `/<SUB>` taken from the shorter `<PREFIX>` across marks `<OFFSET>` through `<OFFSET> + [number of /<SUB> prefixes in <PREFIX>] - 1`. (`<PREFIX>` is an IPv6 CIDR prefix, `<OFFSET>` is an unsigned 32-bit integer that defaults to zero and `<SUB>` is a prefix length that defaults to 128.)

The table _must_ be `mangle` and the chain _must_ be `PREROUTING`, otherwise ip6tables will be unable to find MARKSRCRANGE. You should be able to include more match logic but `--source` _must_ be present. If you get cryptic errors, try running `dmesg | tail`.

This is otherwise standard ip6tables fare. You can, for example, see your rules via the usual `ip6tables -t mangle -L PREROUTING`:

	# ip6tables -t mangle -L PREROUTING
	Chain PREROUTING (policy ACCEPT)
	target       prot opt source           destination 
	MARKSRCRANGE all      2001:db8::/112   anywhere    marks 0-65535 (0x0-0xffff) /112/128 
	MARKSRCRANGE all      2001:db8:1::/112 anywhere    marks 65536-131071 (0x10000-0x1ffff) /112/128
	MARKSRCRANGE all      2001:db8:2::/112 anywhere    marks 524288-589823 (0x80000-0x8ffff) /112/128

## Configuration Testing

Particularly since `--sub-prefix-len` can complicate things, you can find in the `test` folder the source code for a small binary that can help you review the marks your rules are expected to generate.

All the binary does is print the mark/prefix combinations that will result from a MARKSRCRANGE rule. You must invoke it using the same `--source`, `--mark-offset` and `--sub-prefix-len` arguments from your rule. For example,

	$ cd <MARKSRCRANGE>/test
	$ make
	$ ./test.out --source 2001:db8:1234:5600::/56 --mark-offset 256 --sub-prefix-len 64
	Mark		Prefix
	256	0x100	2001:db8:1234:5600::/64
	257	0x101	2001:db8:1234:5601::/64
	258	0x102	2001:db8:1234:5602::/64
	259	0x103	2001:db8:1234:5603::/64
	260	0x104	2001:db8:1234:5604::/64
	...
	510	0x1fe	2001:db8:1234:56fe::/64
	511	0x1ff	2001:db8:1234:56ff::/64
	
The above output states that a rule that would use the given configuration should mark clients matching `2001:db8:1234:5600::/64` as `256`, clients matching `2001:db8:1234:5601::/64` as `257`, etc.

A more involved and bulletproof method to tell whether your rules are doing what you want is to enable debugging on the kernel module:

	$ # Obtain a debugging-enabled binary.
	$ cd <MARKSRCRANGE>/mod
	$ make MARKSRCRANGE_FLAGS=-DDEBUG
	$ sudo make install
	$
	$ # Make sure the old binary will not interfere.
	$ sudo ip6tables -t mangle -F
	$ sudo modprobe -r xt_MARKSRCRANGE
	$
	$ # Reinsert your rules, since you just removed them.
	$ sudo ip6tables -t mangle -A PREROUTING -j MARKSRCRANGE ...
	$
	$ # Read the kernel log.
	$ dmesg -t
	MARKSRCRANGE: Packet from 2001:db8:1234:560f::2 was marked 15.
	MARKSRCRANGE: Packet from 2001:db8:1234:560f::2 was marked 15.
	MARKSRCRANGE: Packet from 2001:db8:1234:56ff::2 was marked 255.
	MARKSRCRANGE: Packet from 2001:db8:1234:56ff::2 was marked 255.

Remember to revert this when you're done testing to avoid heavy logging. (You will have to `ip6tables -F` and `modprobe -r` the module again!)

## TODO

1. Test in environments other than Ubuntu 14.04, kernel 3.13.
2. Add configuration script and DKMS.

