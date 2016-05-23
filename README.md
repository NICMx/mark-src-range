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

	ip6tables -t mangle -A PREROUTING --source 2001:db8:0::/120 -j MARKSRCRANGE --mark-offset 0
	ip6tables -t mangle -A PREROUTING --source 2001:db8:1::/120 -j MARKSRCRANGE --mark-offset 256

Is the same as this:

	ip6tables -t mangle -A PREROUTING --source 2001:db8:0::0 -j MARK --set-mark 0
	ip6tables -t mangle -A PREROUTING --source 2001:db8:0::1 -j MARK --set-mark 1
	...
	ip6tables -t mangle -A PREROUTING --source 2001:db8:0::FF -j MARK --set-mark 255

	ip6tables -t mangle -A PREROUTING --source 2001:db8:1::0 -j MARK --set-mark 256
	ip6tables -t mangle -A PREROUTING --source 2001:db8:1::1 -j MARK --set-mark 257
	...
	ip6tables -t mangle -A PREROUTING --source 2001:db8:1::FF -j MARK --set-mark 511

## Installation

Kbuild only and no configuration script yet; sorry.

	# apt-get install iptables-dev
	$ cd src
	$ make
	# make install

## Usage

	ip6tables -t mangle -A PREROUTING --source <PREFIX> -j MARKSRCRANGE [--mark-offset <OFFSET>]

Will distribute the `<PREFIX>` clients across marks `<OFFSET>` through `<OFFSET> + [number of clients in <PREFIX>] - 1`. (`<PREFIX>` is an IPv6 CIDR prefix and `<OFFSET>` is an unsigned 32-bit integer that defaults to zero.)

The table _must_ be `mangle` and the chain _must_ be `PREROUTING`, otherwise ip6tables will be unable to find MARKSRCRANGE. You should be able to include more match logic but `--source` _must_ be present. If you get cryptic errors, try running `dmesg | tail`.

This is otherwise standard ip6tables fare. You can, for example, see your rules via the usual `ip6tables -t mangle -L PREROUTING`:

	# ip6tables -t mangle -L PREROUTING
	Chain PREROUTING (policy ACCEPT)
	target       prot opt source           destination 
	MARKSRCRANGE all      2001:db8::/112   anywhere    marks 0-65535 (0x0-0xffff); addresses 2001:db8:: - 2001:db8::ffff 
	MARKSRCRANGE all      2001:db8:1::/112 anywhere    marks 65536-131071 (0x10000-0x1ffff); addresses 2001:db8:1:: - 2001:db8:1::ffff 
	MARKSRCRANGE all      2001:db8:2::/112 anywhere    marks 524288-589823 (0x80000-0x8ffff); addresses 2001:db8:2:: - 2001:db8:2::ffff

