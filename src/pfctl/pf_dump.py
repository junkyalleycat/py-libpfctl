#!/usr/bin/env python3

import datetime
import binascii
import ctypes
import json
import io
import argparse
import asyncio
import sys
import ipaddress
import socket
from socket import ntohl, ntohs
import functools

from . import pf
from . import pfctl
from . import cmisc

@functools.lru_cache
def get_addr_name(addr):
    try:
        name = socket.gethostbyaddr(str(addr))[0]
    except socket.gaierror:
        name = addr
    except socket.herror:
        name = addr
    return name

@functools.lru_cache
def get_host(name):
    return socket.gethostbyname(name)

def parse_filter(x):
    def test(locals):
        return eval(x, {}, locals)
    return test

class empty:
    def __getattr__(self, name):
        return self
    def __getitem__(self, k):
        return self

empty = empty()

async def amain():
    parser = argparse.ArgumentParser()
    parser.add_argument('--status', action='store_true')
    parser.add_argument('-x')
    parser.add_argument('-p', action='append', default=[])
    parser.add_argument('-d', action='append', default=[])
    parser.add_argument('--hex-id', action='store_true')
    args = parser.parse_args()

    if args.x is None:
        x_filter = lambda _: True
    else:
        x_filter = parse_filter(args.x)

    def parse_pf_addr(addr, af):
        if af == socket.AF_INET:
            return ipaddress.ip_address(bytes(addr.v4))
        elif af == socket.AF_INET6:
            return ipaddress.ip_address(bytes(addr.v6))
        else:
            raise Exception(f'unknown af: {af}')

    def state_mapper():
        def mapper(field):
            if isinstance(field.parent, pfctl.pfctl_state):
                if field.path.stem == 'entry':
                    return None
                elif (field.path.stem in ['id', 'creatorid']) and args.hex_id:
                    return hex(field.value)
                elif field.path.stem in ['ifname', 'orig_ifname', 'rt_ifname']:
                    return ctypes.string_at(field.value).decode()
                elif field.path.stem == 'rt_addr':
                    af = field.parent.key[0].af
                    return parse_pf_addr(field.value, af)
            elif isinstance(field.parent, pfctl.pfctl_state_key):
                if field.path.stem == 'addr':
                    af = field.parent.af
                    return [parse_pf_addr(field.value[0], af), parse_pf_addr(field.value[1], af)]
            return field
        return mapper

    def counter_mapper(field):
        if isinstance(field.parent, pfctl.pfctl_status_counter):
            if (field.path.stem == 'id') and (args.hex_id):
                return hex(field.value)
            elif field.path.stem == 'entry':
                return None
            elif field.path.stem == 'name':
                return ctypes.string_at(field.value).decode()
        return field

    def status_mapper(field):
        if isinstance(field.parent, pfctl.pfctl_status):
            if field.path.stem == 'ifname':
                return ctypes.string_at(field.value).decode()
            elif (field.path.stem == 'hostid') and (args.hex_id):
                return hex(field.value)
            elif (field.path.stem == 'pf_chksum') and (args.hex_id):
                return f'0x{binascii.hexlify(bytes(field.value)).decode()}'
            elif isinstance(field.value, pfctl.pfctl_status_counters):
                stats = []
                for counter_p in cmisc.TAILQ_FOREACH(field.value, 'entry'):
                    stats.append(cmisc.cdata_to_record(counter_p.contents, counter_mapper))
                return stats
        return field

    # TODO not a big fan of this, but default
    # json encoder happily converts tuples, so
    # if i'm using namedtuple in record, then i need
    # to do something like this
    def reverse(o):
        if type(o) in (int,str,bool,):
            return o
        elif type(o) is list:
            return [reverse(e) for e in o]
        elif type(o) in (ipaddress.IPv4Address, ipaddress.IPv6Address):
            return str(o)
        elif type(o) is type(None):
            return None
        elif type(o) is datetime.datetime:
            return str(o)
        elif type(o) is datetime.timedelta:
            return str(o)
        elif isinstance(o, tuple):
            data = {}
            for fieldname in o._fields:
                data[fieldname] = reverse(getattr(o, fieldname))
            return data
        else:
            raise Exception(f'unknown type: {type(o)}')

    def x_select(state):
        def _(x):
            return state if x else empty
        return _

    def x_dig4(name, alt=None):
        try:
            ip = ipaddress.IPv4Address(name)
        except ValueError:
            ip = None
        try:
            if ip is None:
                return ipaddress.IPv4Address(socket.gethostbyname(name))
            else:
                return socket.gethostbyaddr(str(ip))[0]
        except:
            if alt is None:
                raise
            return alt

    with open('/dev/pf', 'rb') as pfdev:
        if args.status:
            with pfctl.get_status(pfdev) as status:
                print(json.dumps(reverse(cmisc.cdata_to_record(status, status_mapper))))
            return

        with pfctl.get_states(pfdev) as states:
            for state_p in cmisc.TAILQ_FOREACH(states.states, 'entry'):
                state = state_p.contents
                mapper = state_mapper()
                state = cmisc.cdata_to_record(state, mapper)
    
                localz = {
                    'ip': ipaddress.ip_address,
                    'dig4': x_dig4,
                    'PF_INOUT': pf.PF_INOUT,
                    'PF_IN': pf.PF_IN,
                    'PF_OUT': pf.PF_OUT,
                    'PF_SK_WIRE': pf.PF_SK_WIRE,
                    'PF_SK_STACK': pf.PF_SK_STACK,
                    'PF_SK_BOTH': pf.PF_SK_BOTH,
                    'empty': empty
                }
    
                for decl in args.d:
                    name, _, x = decl.partition(':')
                    localz[name] = eval(x, globals=localz)
    
                for p in args.p:
                    varz = localz.copy()
                    varz.update({
                        'state': state,
                        'x': state,
                        'select': x_select(state)
                    })
                    state = eval(p, varz, {})
                    if state == empty:
                        break
    
                if state != empty:
                    print(json.dumps(reverse(state)))


def main():
    asyncio.run(amain())

