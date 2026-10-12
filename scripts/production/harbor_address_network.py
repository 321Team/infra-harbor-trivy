"""Strict projection of observed Docker bridge transitions, not new policy.

Only kernel link-local routes of proven reciprocal veth peers are transient.
Network configuration/unknown fields and all other routes remain compared.
"""
from copy import deepcopy
import ipaddress
import math
import re

from harbor_address_compose import require
from harbor_address_sequence import fingerprint, SERVICES


def network_projection(row):
    require(type(row) is dict, 'NETWORK_SCHEMA')
    result=deepcopy(row)
    for key in ('Containers','Peers'):
        result.pop(key,None)
    status=result.get('Status')
    require(type(status) is dict and type(status.get('IPAM')) is dict and
            type(status['IPAM'].get('Subnets')) is dict, 'NETWORK_STATUS_SCHEMA')
    for subnet,values in status['IPAM']['Subnets'].items():
        require(type(subnet) is str and str(ipaddress.ip_network(subnet))==subnet and
                type(values) is dict, 'NETWORK_SUBNET_SCHEMA')
        # Preserve the existence of each counter, subnet, and every unknown key.
        for key in ('IPsInUse','DynamicIPsAvailable'):
            require(type(values.get(key)) is int and values[key]>=0, 'NETWORK_COUNTER_SCHEMA')
            values[key]=0
    return result


def link_map(rows):
    require(type(rows) is list and all(type(r) is dict for r in rows), 'NETWORK_LINK_SCHEMA')
    result={}
    names=set()
    for row in rows:
        require(type(row.get('ifindex')) is int and row['ifindex']>0 and
                type(row.get('ifname')) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',row['ifname']) and
                row['ifindex'] not in result and row['ifname'] not in names, 'NETWORK_LINK_ID')
        result[row['ifindex']]=row
        names.add(row['ifname'])
    return result



def link_projection(rows):
    """Normalize documented runtime timers, retain configuration and unknowns.

    The input rows are not mutated; this function does not persist raw evidence.
    Presence and types are preserved. No wildcard timer/key removal.
    """
    links=deepcopy(link_map(rows))
    def normalize(data, timers, counters=()):
        require(type(data) is dict, 'NETWORK_LINK_DETAILS')
        for key in timers:
            if key in data:
                value=data[key]
                require(type(value) in (int,float) and math.isfinite(value) and
                        value>=0, 'NETWORK_LINK_TIMER')
                data[key]=0
        for key in counters:
            if key in data:
                require(type(data[key]) is int and data[key]>=0, 'NETWORK_LINK_COUNTER')
                data[key]=0
    for row in links.values():
        info=row.get('linkinfo',{})
        require(type(info) is dict, 'NETWORK_LINK_DETAILS')
        if info.get('info_kind')=='bridge' and 'info_data' in info:
            normalize(info['info_data'],
                      ('hello_timer','tcn_timer','topology_change_timer','gc_timer'),
                      ('fdb_n_learned',))
        if info.get('info_slave_kind')=='bridge' and 'info_slave_data' in info:
            normalize(info['info_slave_data'],
                      ('hold_timer','message_age_timer','forward_delay_timer'))
    return [links[index] for index in sorted(links)]

def owned_links(host_links, endpoints, peers, *, bridge):
    """endpoints: exact Docker ID -> MAC. peers: independently read netns links.

    Both ends' kernel ifindex/link_index and endpoint MAC must agree. A bridge
    member count or a name starting with veth is not ownership proof.
    """
    links=link_map(host_links)
    bridges=[r for r in links.values() if r['ifname']==bridge]
    require(len(bridges)==1 and bridges[0].get('linkinfo',{}).get('info_kind')=='bridge', 'NETWORK_BRIDGE')
    require(type(endpoints) is dict and endpoints and set(endpoints)==set(peers), 'NETWORK_PEER_SET')
    owned={}
    for cid,mac in endpoints.items():
        require(re.fullmatch('[0-9a-f]{64}',cid) and type(mac) is str and
                re.fullmatch('(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',mac), 'NETWORK_ENDPOINT')
        matches=[r for r in link_map(peers[cid]).values()
                 if r.get('address')==mac and r.get('linkinfo',{}).get('info_kind')=='veth']
        require(len(matches)==1, 'NETWORK_PEER_MAC')
        peer=matches[0]
        host=links.get(peer.get('link_index'),{})
        require(host.get('linkinfo',{}).get('info_kind')=='veth' and
                host.get('master')==bridge and host.get('link_index')==peer['ifindex'] and
                host['ifname'] not in owned, 'NETWORK_PEER_PAIR')
        owned[host['ifname']]=host
    members={r['ifname'] for r in links.values() if r.get('master')==bridge}
    require(members==set(owned),'NETWORK_UNOWNED_BRIDGE_MEMBER')
    return owned


def address_readiness(rows, owned):
    """Read-only proof of DAD, not permission to ignore an absent address.

    Supported contract: one EUI-64 link-local /64 per owned host veth.
    Disabled IPv6, other generation modes and DAD failures fail closed.
    """
    indexed=link_map(rows)
    pending=set()
    for name,link in owned.items():
        row=indexed.get(link['ifindex'],{})
        require(row.get('ifname')==name and type(row.get('addr_info')) is list and
                len(row['addr_info'])==1, 'NETWORK_ADDRESS_SET')
        address=row['addr_info'][0]
        require(type(address) is dict and address.get('family')=='inet6' and
                address.get('scope')=='link' and address.get('prefixlen')==64 and
                address.get('local')==link_local(link), 'NETWORK_ADDRESS_IDENTITY')
        for flag in ('tentative','dadfailed','optimistic'):
            require(type(address.get(flag,False)) is bool, 'NETWORK_ADDRESS_FLAGS')
        require(not address.get('dadfailed',False) and not address.get('optimistic',False),
                'NETWORK_ADDRESS_DAD_FAILED')
        if address.get('tentative',False):pending.add(name)
    return pending


def link_local(link):
    mac=link.get('address','')
    require(type(mac) is str and re.fullmatch('(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',mac),'NETWORK_HOST_MAC')
    octets=bytearray.fromhex(mac.replace(':',''));octets[0]^=2
    eui=octets[:3]+b'\xff\xfe'+octets[3:]
    return str(ipaddress.IPv6Address(int(ipaddress.IPv6Address('fe80::'))|int.from_bytes(eui,'big')))


def network_progress(first, last):
    """Only an identical topology's PENDING -> READY is a normal transition."""
    for row in (first,last):
        require(type(row) is dict and set(row)=={'topology_sha256','pending_services'} and
                type(row['topology_sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['topology_sha256']) and
                type(row['pending_services']) is list and
                all(type(s) is str and s in SERVICES for s in row['pending_services']) and
                row['pending_services']==sorted(set(row['pending_services'])), 'NETWORK_PROGRESS_SCHEMA')
    require(first['topology_sha256']==last['topology_sha256'] and
            set(last['pending_services'])<=set(first['pending_services']), 'NETWORK_READINESS_REGRESSED')
    # Conservative: the entire observation must be ready before advancing.
    return deepcopy(first)


def route_projection(routes, owned, *, pending=frozenset()):
    """Canonical stable routes. Refuse unexpected routes even on a proven veth."""
    require(type(routes) is list and all(type(r) is dict for r in routes), 'NETWORK_ROUTES_SCHEMA')
    require(type(pending) in (set,frozenset) and pending<=set(owned), 'NETWORK_PENDING_SET')
    stable=[];seen=set();counts={name:set() for name in owned}
    for row in routes:
        digest=fingerprint(row)
        require(digest not in seen,'NETWORK_DUPLICATE_ROUTE');seen.add(digest)
        name=row.get('dev')
        if name not in owned:
            stable.append(deepcopy(row))
            continue
        local=link_local(owned[name])
        common=dict(dev=name,protocol='kernel',flags=[],pref='medium')
        allowed={
            'prefix':dict(common,dst='fe80::/64',metric=256),
            'local':dict(common,type='local',dst=local,table='local',metric=0),
            'multicast':dict(common,type='multicast',dst='ff00::/8',table='local',metric=256)}
        matches=[kind for kind,wanted in allowed.items() if row==wanted]
        require(len(matches)==1 and matches[0] not in counts[name],'NETWORK_DYNAMIC_ROUTE')
        counts[name].add(matches[0])
    require(all(kinds=={'prefix','local','multicast'} or
                (name in pending and kinds=={'prefix','multicast'})
                for name,kinds in counts.items()),'NETWORK_DYNAMIC_ROUTE_SET')
    return sorted(stable,key=fingerprint)
