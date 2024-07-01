#!/usr/bin/env python3

import json
import io
import argparse
import asyncio
import sys
from ipaddress import ip_address
from socket import *

from .pf import *

cache={}

def get_addr_name(addr):
    return addr
    global cache
    if addr in cache:
        return cache[addr]
    try:
        name = gethostbyaddr(str(addr))[0]
    except gaierror:
        name = addr
    except herror:
        name = addr
    cache[addr] = name
    return name

def parse_filter(x):
    def test(locals):
        return eval(x, {}, locals)
    return test

async def amain():
    parser = argparse.ArgumentParser()
    parser.add_argument('-x')
    parser.add_argument('-d', action='append', default=[])
    args = parser.parse_args()

    if args.x is None:
        x_filter = lambda _: True
    else:
        x_filter = parse_filter(args.x)

    with open('/dev/pf', 'rb') as pfdev:
        for state in get_states(pfdev):
#            if state.direction == PF_OUT:
#                src = state.src
#                dst = state.dst
#                sk = state.key[PF_SK_STACK]
#                nk = state.key[PF_SK_WIRE]
#                if state.proto in [IPPROTO_ICMP, IPPROTO_ICMPV6]:
#                    sk.port[0] = nk.port[0]
#            else:
#                src = state.dst
#                dst = state.src
#                sk = state.key[PF_SK_WIRE]
#                nk = state.key[PF_SK_STACK]
#                if state.proto in [IPPROTO_ICMP, IPPROTO_ICMPV6]:
#                    sk.port[1] = nk.port[1]
#            ifname = cstr_to_str(state.ifname, 'ascii')
#            output = io.StringIO()
#            output.write(f'{ifname} ')
#            proto = getprotobynumber(state.proto) or state.proto
#            output.write(f'{proto} ')
#            nk_addr1 = pf_addr_to_ip_address(nk.addr[1], state.af)
#            sk_addr1 = pf_addr_to_ip_address(sk.addr[1], state.af)
#            output.write(f'{get_addr_name(nk_addr1)}:{ntohs(nk.port[1])}')
#            if (nk_addr1 != sk_addr1) or (nk.port[1] != sk.port[1]):
#                output.write(f' ({get_addr_name(sk_addr1)}:{ntohs(sk.port[1])})')
#            if state.direction == PF_OUT:
#                output.write(' -> ')
#            else:
#                output.write(' <- ')
#            nk_addr0 = pf_addr_to_ip_address(nk.addr[0], state.af)
#            sk_addr0 = pf_addr_to_ip_address(sk.addr[0], state.af)
#            output.write(f'{get_addr_name(nk_addr0)}:{ntohs(nk.port[0])}')
#            if (nk_addr0 != sk_addr0) or (nk.port[0] != sk.port[0]):
#                output.write(f' ({get_addr_name(sk_addr0)}:{ntohs(sk.port[0])})')
#            output.write("\n")

            varz = {
                'state': state.to_friendly(),
                'ip': ip_address,
                'PF_INOUT': PF_INOUT,
                'PF_IN': PF_IN,
                'PF_OUT': PF_OUT,
                'PF_SK_WIRE': PF_SK_WIRE,
                'PF_SK_STACK': PF_SK_STACK,
                'PF_SK_BOTH': PF_SK_BOTH
            }
            for decl in args.d:
                name, _, x = decl.partition(':')
                varz[name] = eval(x, varz)

            if x_filter(varz):
                print(json.dumps(state, cls=JSONEncoder))

def main():
    asyncio.run(amain())

