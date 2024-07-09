#!/usr/bin/env python3

from contextlib import contextmanager
from ctypes import *

from .cmisc import *
from .pf import *

# libpfctl.h
class pfctl_status_counter(Structure): pass
pfctl_status_counter._fields_ = [
        ('id', c_uint64,),
        ('counter', c_uint64,),
        ('name', c_char_p,),
        ('entry', TAILQ_ENTRY(pfctl_status_counter),),
    ]
pfctl_status_counters = TAILQ_HEAD(pfctl_status_counter)

# libpfctl.h
class pfctl_status(Structure):
    _fields_ = [
        ('running', c_bool,),
        ('since', c_uint32,),
        ('debug', c_uint32,),
        ('hostid', c_uint32,),
        ('states', c_uint64,),
        ('src_nodes', c_uint64,),
        ('ifname', c_char*IFNAMSIZ,),
        ('pf_chksum', c_uint8*PF_MD5_DIGEST_LENGTH,),
        ('syncookies_active', c_bool,),
        ('reass', c_uint32,),
        ('counters', pfctl_status_counters,),
        ('lcounters', pfctl_status_counters,),
        ('fcounters', pfctl_status_counters,),
        ('scounters', pfctl_status_counters,),
        ('pcounters', c_uint64*2*2*3,),
        ('bcounters', c_uint64*2*2,),
    ]

# libpfctl.h
class pfctl_state_peer(Structure):
    _fields_ = [
        ('seqlo', c_uint32),
        ('seqhi', c_uint32),
        ('seqdiff', c_uint32),
        ('state', c_uint8),
        ('wscale', c_uint8)
    ]

# libpfctl.h
class pfctl_state_key(Structure):
    _fields_ = [
        ('addr', pf_addr*2),
        ('port', c_uint16*2),
        ('af', sa_family_t),
        ('proto', c_uint8)
    ]

# libpfctl.h
class pfctl_state(Structure): pass
pfctl_state._fields_ = [
        ('entry', TAILQ_ENTRY(pfctl_state)),
        ('id', c_uint64),
        ('creatorid', c_uint32),
        ('direction', c_uint8),
        ('src', pfctl_state_peer),
        ('dst', pfctl_state_peer),
        ('rule', c_uint32),
        ('anchor', c_uint32),
        ('nat_rule', c_uint32),
        ('rt_addr', pf_addr),
        ('key', pfctl_state_key*2),
        ('ifname', c_char*IFNAMSIZ),
        ('orig_ifname', c_char*IFNAMSIZ),
        ('packets', c_uint64*2),
        ('bytes', c_uint64*2),
        ('creation', c_uint32),
        ('expire', c_uint32),
        ('pfsync_time', c_uint32),
        ('state_flags', c_uint16),
        ('sync_flags', c_uint32),
        ('qid', c_uint16),
        ('pqid', c_uint16),
        ('dnpipe', c_uint16),
        ('dnrpipe', c_uint16),
        ('log', c_uint8),
        ('rtableid', c_int32),
        ('min_ttl', c_uint8),
        ('set_tos', c_uint8),
        ('max_mss', c_uint16),
        ('set_prio', c_uint8*2),
        ('rt', c_uint8),
        ('rt_ifname', c_char*IFNAMSIZ)
    ]

# libpfctl.h
pfctl_statelist = TAILQ_HEAD(pfctl_state)

# libpfctl.h
class pfctl_states(Structure):
    _fields_ = [
        ('states', pfctl_statelist)
    ]

pfctl_get_state_fn = CFUNCTYPE(c_int, POINTER(pfctl_state), c_void_p)

libpfctl = cdll.LoadLibrary('libpfctl.so')

_pfctl_get_status = libpfctl.pfctl_get_status
_pfctl_get_status.restype = POINTER(pfctl_status)
_pfctl_get_status.argtypes = (c_int,)

_pfctl_free_status = libpfctl.pfctl_free_status
_pfctl_free_status.restype = None
_pfctl_free_status.argtypes = (POINTER(pfctl_status),)

@contextmanager
def get_status(dev):
    status = _pfctl_get_status(dev.fileno())
    assert status
    try:
        yield status.contents
    finally:
        _pfctl_free_status(status)

_pfctl_get_states = libpfctl.pfctl_get_states
_pfctl_get_states.restype = c_int
_pfctl_get_states.argtypes = (c_int, POINTER(pfctl_states),)

_pfctl_free_states = libpfctl.pfctl_free_states
_pfctl_free_states.restype = None
_pfctl_free_states.argtypes = (POINTER(pfctl_states),)

@contextmanager
def get_states(dev):
    states = pfctl_states()
    assert _pfctl_get_states(dev.fileno(), states) == 0
    try:
        yield states
    finally:
        _pfctl_free_states(states)

