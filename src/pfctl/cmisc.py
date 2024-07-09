#!/usr/bin/env python3

from pathlib import PurePath
from collections import namedtuple
from ctypes import *

# constants
IF_NAMESIZE=16              # net/if.h
IFNAMSIZ=IF_NAMESIZE        # net/if.h

# simple type defs
in_addr_t = c_uint32        # sys/types.h
sa_family_t = c_uint8       # sys/_types.h

# netinet/in.h
class in_addr(Structure):
    _fields_ = [
        ('s_addr', in_addr_t),
    ]

# sys/queue.h
def TAILQ_ENTRY(type):
    class TAILQ_ENTRY(Structure):
        _fields_ = [
            ('tqe_next', POINTER(type)),
            ('tqe_prev', POINTER(POINTER(type)))
        ]
    return TAILQ_ENTRY

# sys/queue.h
def TAILQ_HEAD(type):
    class TAILQ_HEAD(Structure):
        _fields_ = [
            ('tqh_first', POINTER(type)),
            ('tqh_last', POINTER(POINTER(type)))
        ] 
    return TAILQ_HEAD

# sys/queue.h
def TAILQ_FOREACH(head, name):
    e = head.tqh_first
    while e:
        yield e
        e = getattr(e.contents, name).tqe_next

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

# netdb.h
class protoent(Structure):
    _fields_ = [
        ('p_name', POINTER(c_char)),
        ('p_aliases', POINTER(POINTER(c_char))),
        ('p_proto', c_int),
    ]

libc = cdll.LoadLibrary('libc.so.7')
_getprotobynumber = libc.getprotobynumber
_getprotobynumber.restype = POINTER(protoent)
_getprotobynumber.argtypes = (c_int,)

def getprotobynumber(value):
    ent_p = _getprotobynumber(value)
    if not ent_p:
        raise Exception()
    return string_at(ent_p.contents.p_name).decode()

# ctype conversion
class Record:
    def __init__(self, name, fieldnames):
        self.name = name
        self.fieldnames = fieldnames

class CDataField(namedtuple('CDataField', ['parents', 'path', 'value'])):

    @property
    def parent(self):
        return self.parents[-1]
       
def cdata_to_record(o, mapper):

    def _helper(field):
#        print(field.path)
        mapped = mapper(field)
        if mapped is not field:
            return mapped

        if type(field.value) in (int, bytes, bool):
            return field.value
        elif isinstance(field.value, Array):
            data = []
            parents = field.parents+[field.value]
            for i in range(len(field.value)):
                subfield = CDataField(parents, field.path.joinpath(str(i)), field.value[i])
                value = _helper(subfield)
                data.append(value)
            return data
        elif isinstance(field.value, (Structure, Union,)):
            data = {}
            parents = field.parents+[field.value]
            for fieldname, _ in field.value._fields_:
                subfield = CDataField(parents, field.path.joinpath(fieldname), getattr(field.value, fieldname))
                value = _helper(subfield)
                data[fieldname] = value
            name = field.value.__class__.__name__
            return namedtuple(name, data.keys(), rename=True)(*data.values())
        else:
            raise Exception(f"unsupported type: {type(field.value)}")

    root = CDataField([None], PurePath(), o)
    return _helper(root)

