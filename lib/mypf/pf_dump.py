#!/usr/bin/env python3

import sys
from socket import *

from . import pf

def get_addr_name(addr):
    try:
        return f'{gethostbyaddr(str(addr))[0]}'
    except gaierror:
        return addr
    except herror:
        return addr

if __name__ == '__main__':
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
            sys.stdout.write(f'{pf.getprotobynumber(state.proto)} ')
            nk_addr1 = pf.pf_addr_to_ip_address(nk.addr[1], state.af)
            sk_addr1 = pf.pf_addr_to_ip_address(sk.addr[1], state.af)
            sys.stdout.write(f'{get_addr_name(nk_addr1)}:{nk.port[1]}')
            if (nk_addr1 != sk_addr1) or (nk.port[1] != sk.port[1]):
                sys.stdout.write(f' ({get_addr_name(sk_addr1)}:{sk.port[1]})')
            if state.direction == pf.PF_OUT:
                sys.stdout.write(' -> ')
            else:
                sys.stdout.write(' <- ')
            nk_addr0 = pf.pf_addr_to_ip_address(nk.addr[0], state.af)
            sk_addr0 = pf.pf_addr_to_ip_address(sk.addr[0], state.af)
            sys.stdout.write(f'{get_addr_name(nk_addr0)}:{nk.port[0]}')
            if (nk_addr0 != sk_addr0) or (nk.port[0] != sk.port[0]):
                sys.stdout.write(f' ({get_addr_name(sk_addr0)}:{sk.port[0]})')
            sys.stdout.write("\n")
