#!/usr/bin/env python3

from pathlib import PurePath
from collections import namedtuple
import base64
import json
from ctypes import *
from fcntl import ioctl
from ipaddress import IPv4Address, IPv6Address

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

# net/pfvar.h
class pfsync_state_scrub(Structure):
    _pack_ = 1
    _fields_ = [
        ('pfss_flags', c_uint16),
        ('pfss_ttl', c_uint8),
        ('scrub_flag', c_uint8),
        ('pfss_ts_mod', c_uint32),
    ]

# net/pfvar.h
class pfsync_state_peer(Structure):
    _pack_ = 1
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
class pfsync_state_key(Structure):
    _pack_ = 1
    _fields_ = [
        ('addr', pf_addr*2),
        ('port', c_uint16*2),
    ]

class Record:
    def __init__(self, name, fieldnames):
        self.name = name
        self.fieldnames = fieldnames

CDataField = namedtuple('CDataField', ['parents', 'parent', 'path', 'value'])

def cdata_to_record(o, *, path=PurePath(), parents=[None], mapper=lambda _: None):
    mapped = mapper(CDataField(parents, parents[-1], path, o))
    if mapped is not None:
        return mapped
    if type(o) in (int, bytes):
        return o
    elif isinstance(o, Array):
        parents.append(o)
        data = []
        for i in range(len(o)):
            data.append(cdata_to_record(o[i], path=path.joinpath(str(i)), parents=parents, mapper=mapper))
        parents.pop()
        return data
    elif isinstance(o, (Structure, Union,)):
        data = {}
        parents.append(o)
        for fieldname, _ in o._fields_:
            data[fieldname] = cdata_to_record(getattr(o, fieldname), path=path.joinpath(fieldname), parents=parents, mapper=mapper)
        parents.pop()
        name = o.__class__.__name__
        return namedtuple(name, data.keys(), rename=True)(*data.values())
    else:
        raise Exception(f"unsupported type: {type(o)}")

# net/pfvar.h
class pfsync_state_1301(Structure):
    _pack_ = 1
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

## net/pfvar.h
#class pfsync_state_1400(Structure):
#    _pack_ = 1
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

class JSONEncoder(json.JSONEncoder):

    def default(self, o):
        if type(o) is bytes:
            return base64.b64encode(o).decode()
        if type(o) in (IPv4Address, IPv6Address):
            return str(o)
        super().default(o)

