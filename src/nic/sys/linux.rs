// Copyright (C) 2016 whitequark@whitequark.org
// Copyright (C) 2019 Andreas Molzer <andreas.molzer@tum.de>
//
// in large parts from `smoltcp` originally distributed under 0-clause BSD
use libc;

pub const SIOCGIFMTU:   libc::c_ulong = 0x8921;
pub const SIOCGIFINDEX: libc::c_ulong = 0x8933;
pub const ETH_P_ALL:    libc::c_short = 0x0003;

pub const TUNSETIFF:    libc::c_ulong = 0x400454CA;
pub const IFF_TAP:      libc::c_int   = 0x0002;
pub const IFF_NO_PI:    libc::c_int   = 0x1000;

