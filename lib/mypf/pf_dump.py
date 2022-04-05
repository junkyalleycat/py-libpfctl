#!/usr/bin/env python3

import asyncio
import sys
from socket import *

from . import pf

cache={}

def get_addr_name(addr):
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

async def main():
    with open('/dev/pf', 'rb') as pfdev:
        for state in pf.get_states(pfdev):
            if state.direction == pf.PF_OUT:
                src = state.src
                dst = state.dst
                sk = state.key[pf.PF_SK_STACK]
                nk = state.key[pf.PF_SK_WIRE]
                if state.proto in [IPPROTO_ICMP, IPPROTO_ICMPV6]:
                    sk.port[0] = nk.port[0]
            else:
                src = state.dst
                dst = state.src
                sk = state.key[pf.PF_SK_WIRE]
                nk = state.key[pf.PF_SK_STACK]
                if state.proto in [IPPROTO_ICMP, IPPROTO_ICMPV6]:
                    sk.port[1] = nk.port[1]
            ifname = pf.cstr_to_str(state.ifname, 'ascii')
            sys.stdout.write(f'{ifname} ')
            proto = pf.getprotobynumber(state.proto) or state.proto
            sys.stdout.write(f'{proto} ')
            nk_addr1 = pf.pf_addr_to_ip_address(nk.addr[1], state.af)
            sk_addr1 = pf.pf_addr_to_ip_address(sk.addr[1], state.af)
            sys.stdout.write(f'{get_addr_name(nk_addr1)}:{ntohs(nk.port[1])}')
            if (nk_addr1 != sk_addr1) or (nk.port[1] != sk.port[1]):
                sys.stdout.write(f' ({get_addr_name(sk_addr1)}:{ntohs(sk.port[1])})')
            if state.direction == pf.PF_OUT:
                sys.stdout.write(' -> ')
            else:
                sys.stdout.write(' <- ')
            nk_addr0 = pf.pf_addr_to_ip_address(nk.addr[0], state.af)
            sk_addr0 = pf.pf_addr_to_ip_address(sk.addr[0], state.af)
            sys.stdout.write(f'{get_addr_name(nk_addr0)}:{ntohs(nk.port[0])}')
            if (nk_addr0 != sk_addr0) or (nk.port[0] != sk.port[0]):
                sys.stdout.write(f' ({get_addr_name(sk_addr0)}:{ntohs(sk.port[0])})')
            sys.stdout.write("\n")

asyncio.run(main())
