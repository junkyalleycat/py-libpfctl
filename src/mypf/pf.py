#!/usr/bin/env python3

from collections import namedtuple
import base64
import json
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
in_addr_t = c_uint32        # sys/types.h
sa_family_t = c_uint8       # sys/_types.h

# netinet/in.h
class in_addr(Structure):
    _fields_ = [
        ('s_addr', in_addr_t),
    ]
    def to_friendly(self):
        return ip_address(bytes(self))

# netinet6/in6.h
# TODO the naming of u6_addr as a field
# does not follow the header, there seems
# to be some name mangling going on in ctypes
# with names with __, so fudge it
class in6_addr(Structure):
    class __u6_addr(Union):
        _fields_ = [
            ('__u6_addr8', c_uint8*16),
            ('__u6_addr16', c_uint16*8),
            ('__u6_addr32', c_uint32*4),
        ]
    _fields_ = [
        ('u6_addr', __u6_addr),
    ]
    def to_friendly(self):
        return ip_address(bytes(self))

# netpfil/pf/pf.h
class pf_addr(Structure):
    class _(Union):
        _fields_ = [
            ('v4', in_addr),
            ('v6', in6_addr),
            ('addr8', c_uint8*16),
            ('addr16', c_uint16*8),
            ('addr32', c_uint32*4),
        ]
    _anonymous_ = ('_',)
    _fields_ = [
        ('_', _),
    ]
    def to_friendly(self, af):
        if af == AF_INET:
            return self.v4.to_friendly()
        elif af == AF_INET6:
            return self.v6.to_friendly()
        assert False

# net/pfvar.h
# TODO packed
class pfsync_state_scrub(Structure):
    _pack_ = True
    _fields_ = [
        ('pfss_flags', c_uint16),
        ('pfss_ttl', c_uint8),
        ('scrub_flag', c_uint8),
        ('pfss_ts_mod', c_uint32),
    ]

# net/pfvar.h
# TODO packed
class pfsync_state_peer(Structure):
    _pack_ = True
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

# net/pfvar.h
# TODO packed
class pfsync_state_key(Structure):
    _pack_ = True
    _fields_ = [
        ('addr', pf_addr*2),
        ('port', c_uint16*2),
    ]
    def to_friendly(self, af, asdict=False):
        fieldnames = [e[0] for e in pfsync_state_key._fields_]
        friendly = namedtuple('pfsync_state_key', fieldnames)
        addrs = [self.addr[0].to_friendly(af), self.addr[1].to_friendly(af)]
        if asdict:
            return friendly(addrs, self.port)._asdict()
        return friendly(addrs, self.port)

def structure_to_data(o):
    data = {}
    for field in o._fields_:
        data[field[0]] = getattr(o, field[0])
    return data

# net/pfvar.h
# TODO packed
class pfsync_state_1301(Structure):
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
    def deepcopy(self):
        return pfsync_state_1301.from_buffer_copy(self)
    def to_friendly(self, *, asdict=False):
        fieldnames = [e[0] for e in pfsync_state_1301._fields_]
        fieldnames.remove('__spare')
        friendly = namedtuple('pfsync_state_1301', fieldnames, rename=True)
        kwargs = structure_to_data(self)
        del kwargs['__spare']
        kwargs['id'] = hex(self.id)
        kwargs['ifname'] = cstr_to_str(self.ifname)
        kwargs['key'] = [e.to_friendly(self.af, asdict=asdict) for e in self.key]
        kwargs['rt_addr'] = self.rt_addr.to_friendly(self.af)
        if asdict:
            return friendly(**kwargs)._asdict()
        return friendly(**kwargs)

## net/pfvar.h
## TODO packed
#class pfsync_state_1400(Structure):
#    _pack_ = True
#    _fields_ = [
#        ('id', c_uint64),
#        ('ifname', c_char*IFNAMSIZ),
#        ('key', pfsync_state_key*2),
#        ('src', pfsync_state_peer),
#        ('dst', pfsync_state_peer),
#        ('rt_addr', pf_addr),
#        ('rule', c_uint32),
#        ('anchor', c_uint32),
#        ('nat_rule', c_uint32),
#        ('creation', c_uint32),
#        ('expire', c_uint32),
#        ('packets', c_uint32*2*2),
#        ('bytes', c_uint32*2*2),
#        ('creatorid', c_uint32),
#        ('af', sa_family_t),
#        ('proto', c_uint8),
#        ('direction', c_uint8),
#        ('state_flags', c_uint16),
#        ('log', c_uint8),
#        ('__spare', c_uint8),
#        ('timeout', c_uint8),
#        ('sync_flags', c_uint8),
#        ('updates', c_uint8),
#        ('qid', c_uint16,),
#        ('pqid', c_uint16,),
#        ('dnpipe', c_uint16,),
#        ('rtableid', c_int32,),
#        ('min_ttl', c_uint8,),
#        ('set_tos', c_uint8,),
#        ('max_mss', c_uint16,),
#        ('set_prio', c_uint8*2,),
#        ('rt', c_uint8,),
#        ('rt_ifname', c_char*IFNAMSIZ),
#    ]

# net/pfvar.h
class pfioc_states(Structure):
    class _(Union):
        _fields_ = [
            ('ps_buf', c_void_p,),
            ('ps_states', POINTER(pfsync_state_1301)),
        ]
    _anonymous_ = ('_',)
    _fields_ = [
        ('ps_len', c_int,),
        ('_', _,),
    ]

## net/pfvar.h
#class pfioc_states_v2(Structure):
#    class _(Union):
#        _fields_ = [
#            ('ps_buf', c_void_p,),
#            ('ps_states', POINTER(pf_state_export),),
#        ]
#    _anonymous_ = ('_',)
#    _fields_ = [
#        ('ps_len', c_int,),
#        ('ps_req_version', c_uint64,),
#        ('_', _,),
#    ]

# netdb.h
class protoent(Structure):
    _fields_ = [
        ('p_name', POINTER(c_char)),
        ('p_aliases', POINTER(POINTER(c_char))),
        ('p_proto', c_int),
    ]

def get_states(pf):
    rq = pfioc_states()
    rq.ps_len = 0
    # create a large enough states buffer to store
    # all the states, the DIO call will constantly
    # return the size needed and the truncated result
    # set, ignore the tuncation and loop until size
    # is sufficient
    while True:
        n = int(rq.ps_len/sizeof(pfsync_state_1301))
        states = (pfsync_state_1301*n)()
        rq.ps_states = states;
        ioctl(pf.fileno(), DIOCGETSTATES, rq)
        if sizeof(states) >= rq.ps_len:
            break
        rq.ps_len *= 2
    n = int(rq.ps_len/sizeof(pfsync_state_1301))
    for i in range(n):
        # once the states object is lost backing memory is freed
        yield states[i].deepcopy()

def pf_addr_to_ip_address(pf_addr, af):
    if af == AF_INET.value:
        return ip_address(bytes(pf_addr.v4))
    elif af == AF_INET6.value:
        return ip_address(bytes(pf_addr.v6))
    raise Exception(f'unknown af: {af}')

libc = cdll.LoadLibrary('libc.so.7')
_getprotobynumber = libc.getprotobynumber
_getprotobynumber.restype = POINTER(protoent)

def getprotobynumber(value):
    ent_p = _getprotobynumber(value)
    if ent_p == 0:
        return None
    return cstr_to_str(ent_p.contents.p_name)

def cstr_to_str(obj, encoding='utf-8'):
# TODO why does this work
    return string_at(obj).decode(encoding=encoding)

def structure_to_data(o):
    data = {}
    for field in o._fields_:
        data[field[0]] = getattr(o, field[0])
    return data

class JSONEncoder(json.JSONEncoder):

    def default(self, o):
        if isinstance(o, Array):
            return list(o)
        elif type(o) == pfsync_state_1301:
            return o.to_friendly(asdict=True)
        elif isinstance(o, Structure):
            return structure_to_data(o)
        elif isinstance(o, Union):
            return structure_to_data(o)
        elif type(o) is bytes:
            return base64.b64encode(o).decode()
        elif type(o) in (IPv4Address, IPv6Address):
            return str(o)
        super().default(o)

