#!/usr/bin/env python3

import json
import io
import argparse
import asyncio
import sys
import ipaddress
import socket
import functools

from . import pf

@functools.lru_cache
def get_addr_name(addr):
    try:
        name = socket.gethostbyaddr(str(addr))[0]
    except socket.gaierror:
        name = addr
    except socket.herror:
        name = addr
    return name

def parse_filter(x):
    def test(locals):
        return eval(x, {}, locals)
    return test

async def amain():
    parser = argparse.ArgumentParser()
    parser.add_argument('-x')
    parser.add_argument('-p', action='append', default=[])
    parser.add_argument('-d', action='append', default=[])
    parser.add_argument('--hex-id', action='store_true')
    parser.add_argument('--resolve', action='store_true')
    args = parser.parse_args()

    if args.x is None:
        x_filter = lambda _: True
    else:
        x_filter = parse_filter(args.x)

    def state_mapper(af):
        def mapper(field):
            if isinstance(field.parent, pf.pfsync_state_1301):
                if field.path.stem == 'ifname':
                    return field.value.decode()
                elif (field.path.stem == 'id') and (args.hex_id):
                    return hex(field.value)
            elif isinstance(field.value, pf.pf_addr):
                if af == socket.AF_INET:
                    addr = ipaddress.ip_address(bytes(field.value.v4))
                elif af == socket.AF_INET6:
                    addr = ipaddress.ip_address(bytes(field.value.v6))
                else:
                    addr = None
                if addr is not None:
                    if args.resolve:
                        return get_addr_name(addr)
                    return addr
            return None
        return mapper

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
        elif isinstance(o, tuple):
            data = {}
            for fieldname in o._fields:
                data[fieldname] = reverse(getattr(o, fieldname))
            return data
        else:
            raise Exception(f'unknown type: {type(o)}')

    def x_select(state):
        def _(x):
            if x:
                return state
            return None
        return _

    with open('/dev/pf', 'rb') as pfdev:
        for state in pf.get_states(pfdev):
            mapper = state_mapper(state.af)
            state = pf.cdata_to_record(state, mapper=mapper)

            localz = {
                'ip': ipaddress.ip_address,
                'PF_INOUT': pf.PF_INOUT,
                'PF_IN': pf.PF_IN,
                'PF_OUT': pf.PF_OUT,
                'PF_SK_WIRE': pf.PF_SK_WIRE,
                'PF_SK_STACK': pf.PF_SK_STACK,
                'PF_SK_BOTH': pf.PF_SK_BOTH
            }

            for decl in args.d:
                name, _, x = decl.partition(':')
                localz[name] = eval(x, localz)


            for p in args.p:
                varz = localz.copy()
                varz.update({
                    'state': state,
                    'select': x_select(state)
                })
                state = eval(p, {}, varz)
                if state is None:
                    break

            if state is not None:
                print(json.dumps(reverse(state)))

#            if x_filter(varz):
#                print(json.dumps(reverse(state)))

def main():
    asyncio.run(amain())

