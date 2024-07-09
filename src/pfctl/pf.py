#!/usr/bin/env python3

from ctypes import *

from .cmisc import *

# netpfil/pf/pf.h
PF_INOUT=0
PF_IN=1
PF_OUT=2

PF_SK_WIRE=0
PF_SK_STACK=1
PF_SK_BOTH=2

PF_MD5_DIGEST_LENGTH=16
PF_RULE_LABEL_SIZE=64
PF_TABLE_NAME_SIZE=32

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

