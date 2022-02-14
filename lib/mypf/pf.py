#!/usr/bin/env python3

from ipaddress import *
from socket import *
from ctypes import *
from fcntl import ioctl

# constants
DIOCGETSTATES=3222291481
IFNAMSIZ=16

PF_INOUT=0
PF_IN=1
PF_OUT=2

PF_SK_WIRE=0
PF_SK_STACK=1
PF_SK_BOTH=2

# simple type defs
in_addr_t = c_uint32
__sa_family_t = c_uint8
sa_family_t = __sa_family_t
caddr_t = POINTER(c_char)

# structure defs
class in_addr(Structure):
    _fields_ = [
        ('s_addr', in_addr_t),
    ]

class in6_addr(Structure):
    class __u6_addr(Union):
        _fields_ = [
            ('__u6_addr8', c_uint8*16),
            ('__u6_addr16', c_uint16*8),
            ('__u6_addr32', c_uint32*4),
        ]
    _fields_ = [
        ('__u6_addr', __u6_addr),
    ]

class pf_addr(Structure):
    class pfa(Union):
        _fields_ = [
            ('v4', in_addr),
            ('v6', in6_addr),
            ('addr8', c_uint8*16),
            ('addr16', c_uint16*8),
            ('addr32', c_uint32*4),
        ]
    _fields_ = [
        ('pfa', pfa),
    ]

class pfsync_state_scrub(Structure):
    _fields_ = [
        ('pfss_flags', c_uint16),
        ('pfss_ttl', c_uint8),
        ('scrub_flag', c_uint8),
        ('pfss_ts_mod', c_uint32),
    ]

class pfsync_state_peer(Structure):
    _fields_ = [
        ('scrub', pfsync_state_scrub),
        ('seqlo', c_uint32),
        ('seqhi', c_uint32),
        ('seqdiff', c_uint32),
        ('max_win', c_uint16),
        ('mss', c_uint16),
        ('state', c_uint8),
        ('wscale', c_uint8),
        ('pad', c_uint8*6),
    ]

class pfsync_state_key(Structure):
    _fields_ = [
        ('addr', pf_addr*2),
        ('port', c_uint16*2),
    ]

class pfsync_state(Structure):
    _pack_ = True
    _fields_ = [
        ('id', c_uint64),
        ('ifname', c_char*IFNAMSIZ),
        ('key', pfsync_state_key*2),
        ('src', pfsync_state_peer),
        ('dst', pfsync_state_peer),
        ('rt_addr', pf_addr),
        ('rule', c_uint32),
        ('anchor', c_uint32),
        ('nat_rule', c_uint32),
        ('creation', c_uint32),
        ('expire', c_uint32),
        ('packets', c_uint32*2*2),
        ('bytes', c_uint32*2*2),
        ('creatorid', c_uint32),
        ('af', sa_family_t),
        ('proto', c_uint8),
        ('direction', c_uint8),
        ('__spare', c_uint8*2),
        ('log', c_uint8),
        ('state_flags', c_uint8),
        ('timeout', c_uint8),
        ('sync_flags', c_uint8),
        ('updates', c_uint8),
    ]

class pfioc_states(Structure):
    class ps_u(Union):
        _fields_ = [
            ('psu_buf', caddr_t),
            ('psu_states', POINTER(pfsync_state)),
        ]
    _fields_ = [
        ('ps_len', c_int),
        ('ps_u', ps_u),
    ]

def get_states(pf):
    rq = pfioc_states()
    rq.ps_len = 0
    while True:
        n = int(rq.ps_len/sizeof(pfsync_state))
        states = (pfsync_state*n)()
        # cast because a pointer to an array is not the same type
        # as a point to the array object (functionally the same though)
        rq.ps_u.psu_states = cast(pointer(states), POINTER(pfsync_state))
        ioctl(pf.fileno(), DIOCGETSTATES, rq)
        if sizeof(states) >= rq.ps_len:
            break
        rq.ps_len *= 2
    n = int(rq.ps_len/sizeof(pfsync_state))
    for i in range(n):
        state = pfsync_state()
        # copy the state data because once states is lost
        # the memory backing the state objects in it is lost
        memmove(pointer(state), pointer(states[i]), sizeof(pfsync_state))
        yield state

def pf_addr_to_ip_address(pf_addr, af):
    if af == AF_INET.value:
        return ip_address(bytes(pf_addr.pfa.v4))
    elif af == AF_INET6.value:
        return ip_address(bytes(pf_addr.pfa.v6))
    raise Exception(f'unknown af: {af}')

def getprotobynumber(value):
    if value == IPPROTO_TCP:
        return 'tcp'
    elif value == IPPROTO_UDP:
        return 'udp'
    elif value == IPPROTO_ICMP:
        return 'icmp'
    elif value == IPPROTO_ICMPV6:
        return 'icmpv6'
    elif value == IPPROTO_IGMP:
        return 'igmp'
    raise Exception(f'unknown proto: {value}')

def cstr_to_str(cstr, encoding='utf-8'):
    return cstr.split(b'\0', 1)[0].decode(encoding=encoding)

