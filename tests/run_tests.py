#!/usr/bin/env python3
"""
run_tests.py — assertion-based test suite for the ASUS router ingest pipeline.

Usage:
    python3 tests/run_tests.py                    # synthetic tests only (CI mode)
    python3 tests/run_tests.py path/to/syslog.txt # adds bulk validation pass

Exit code 0 = all pass.  Non-zero = failures (safe to use in GitHub Actions).
"""

import sys
import os
import re

# Allow running from repo root or from tests/ directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from simulate_v9 import entry_pipeline, run_bulk

# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------

PASS = 0
FAIL = 0


def check(name, line, source_ip='192.0.2.1:514', **assertions):
    """Run one log line through the pipeline and evaluate field assertions."""
    global PASS, FAIL
    try:
        ctx = entry_pipeline(line, source_ip)
    except Exception as exc:
        print(f'FAIL  {name}')
        print(f'      EXCEPTION: {exc}')
        FAIL += 1
        return

    failures = []
    for dotted_field, expected in assertions.items():
        field  = dotted_field.replace('__', '.')
        actual = ctx.get_path(field)
        ok     = expected(actual) if callable(expected) else actual == expected
        if not ok:
            failures.append(f'  {field}: expected {expected!r}, got {actual!r}')

    if failures:
        print(f'FAIL  {name}')
        for f in failures:
            print(f)
        FAIL += 1
    else:
        print(f'PASS  {name}')
        PASS += 1


def not_wl_interface(v):
    """Assert value doesn't look like a wireless interface name (the v1-v8 bug)."""
    return v is None or not re.match(r'^wl\d+(\.\d+)?$', str(v))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

print('=' * 60)
print('ASUS Router Pipeline — Synthetic Test Suite')
print('=' * 60)

# --- Bug regression: process.name must never be a wireless interface name ---

check(
    'hostapd STA associated — no hostname (original bug case)',
    'Jun 10 12:06:18 hostapd: wl1.2: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated',
    source_ip='192.0.2.2:514',
    **{'process.name': 'hostapd',
       'event.dataset': 'wireless',
       'event.action': 'wireless-associated',
       'event.outcome': 'success',
       'source.mac': 'AA-BB-CC-DD-EE-FF',
       'asus.wireless.interface': 'wl1.2',
       'observer.name': 'GT-AXE16000'}
)

check(
    'hostapd STA associated — underscore hostname (v4 edge case)',
    'Jun 10 12:06:18 RT-BE98_Pro hostapd: wl1.2: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated',
    source_ip='192.0.2.2:514',
    **{'process.name': 'hostapd',
       'event.dataset': 'wireless',
       'event.action': 'wireless-associated',
       'syslog.host': 'RT-BE98_Pro',
       'host.name': 'RT-BE98_Pro'}
)

check(
    'hostapd STA associated — WITH <PRI> prefix',
    '<134>Jun 10 12:06:18 hostapd: wl0.1: STA 11:22:33:44:55:66 IEEE 802.11: associated',
    **{'process.name': 'hostapd',
       'event.dataset': 'wireless',
       'syslog.priority': 134}
)

check(
    'process.name is never a wireless interface name — regression guard',
    'Jun 10 12:06:18 hostapd: wl1.2: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated',
    source_ip='192.0.2.2:514',
    **{'process.name': not_wl_interface}
)

check(
    'hostapd STA disassociated',
    'Jun 10 12:06:19 hostapd: wl1.2: STA aa:bb:cc:dd:ee:ff IEEE 802.11: disassociated',
    **{'event.action': 'wireless-disassociated',
       'event.outcome': 'failure'}
)

check(
    'hostapd WPA pairwise key handshake',
    'Jun 10 12:06:21 hostapd: wl1.2: STA aa:bb:cc:dd:ee:ff WPA: pairwise key handshake completed (RSN)',
    **{'event.action': 'wireless-wpa-pairwise-key-handshake-completed',
       'event.outcome': 'success'}
)

check(
    'hostapd channel switch',
    'Jun 10 12:06:23 hostapd: wl1.2: IEEE 802.11 driver had channel switch: freq=5180',
    **{'event.action': 'wireless-channel-switch',
       'event.dataset': 'wireless'}
)

# --- wlceventd ---

check(
    'wlceventd auth — Successful',
    'Jun 10 12:06:18 wlceventd: wlceventd_proc_event(685): wl3.1: Auth 34:04:9E:B1:1F:46, status: Successful (0), rssi:-47',
    source_ip='192.0.2.2:514',
    **{'event.dataset': 'wireless',
       'event.action': 'wireless-auth',
       'event.outcome': 'success',
       'asus.wireless.rssi': -47,
       'asus.wireless.interface': 'wl3.1',
       'source.mac': '34-04-9E-B1-1F-46'}
)

check(
    'wlceventd deauth_ind',
    'Jun 10 12:06:18 wlceventd: wlceventd_proc_event(645): wl3.1: Deauth_ind 34:04:9E:B1:1F:46, status: 0, reason: Unspecified reason (1), rssi:0',
    **{'event.action': 'wireless-deauth_ind',
       'event.type': ['connection', 'end'],
       'event.outcome': 'failure',
       'asus.wireless.reason': lambda v: v is not None}
)

# --- kernel wireless driver errors ---

check(
    'kernel SBF radio init — routes to wireless not system',
    'Jun 10 12:16:06 kernel: SBF: dhd0: INIT [a4:38:cc:97:c6:0a] ID 65535 BFW 65535 THRSH 2048',
    **{'event.dataset': 'wireless',
       'event.action': 'wireless-sbf-init',
       'asus.wireless.driver': 'dhd0',
       'asus.wireless.sbf_id': 65535,
       'source.mac': 'A4-38-CC-97-C6-0A'}
)

check(
    'kernel WLC_SCB_DEAUTHORIZE — routes to wireless not system',
    'Jun 10 12:16:10 kernel: WLC_SCB_DEAUTHORIZE error (-30)',
    **{'event.dataset': 'wireless',
       'event.action': 'wireless-kernel-deauthorize-error',
       'event.outcome': 'failure'}
)

check(
    'kernel WLC_SCB_DEAUTHENTICATE_FOR_REASON — routes to wireless',
    'Jun 10 12:16:11 kernel: WLC_SCB_DEAUTHENTICATE_FOR_REASON err',
    **{'event.dataset': 'wireless',
       'event.action': 'wireless-kernel-deauthenticate-error'}
)

# --- firewall ---

check(
    'firewall ACCEPT — full field extraction',
    'Jun 10 12:05:43 kernel: ACCEPT IN=br0 OUT=eth0 MAC=cc:28:aa:fe:56:60:a8:a1:59:53:61:4b:08:00 SRC=192.0.2.196 DST=150.171.23.11 LEN=52 TOS=0x00 PREC=0x00 TTL=127 ID=55498 DF PROTO=TCP SPT=55133 DPT=443 SEQ=727969276 ACK=0 WINDOW=64240 RES=0x00 SYN URGP=0',
    **{'event.dataset': 'firewall',
       'event.action': 'accept',
       'event.outcome': 'success',
       'observer.type': 'firewall',
       'source.ip': '192.0.2.196',
       'destination.ip': '150.171.23.11',
       'source.port': 55133,
       'destination.port': 443,
       'network.transport': 'tcp',
       'network.direction': 'outbound',
       'asus.firewall.ttl': 127}
)

check(
    'firewall DROP — inbound direction, mark field',
    'Jun 10 12:05:49 kernel: DROP IN=eth0 OUT= MAC=cc:28:aa:fe:56:60:d0:fc:d0:6d:93:c1:08:00 SRC=91.191.209.74 DST=71.132.186.67 LEN=40 TOS=0x00 PREC=0x00 TTL=237 ID=47708 PROTO=TCP SPT=53768 DPT=16800 SEQ=3601285567 ACK=0 WINDOW=1024 RES=0x00 SYN URGP=0 MARK=0x8000000',
    **{'event.action': 'drop',
       'event.outcome': 'failure',
       'network.direction': 'inbound',
       'asus.firewall.mark': '0x8000000'}
)

# --- dnsmasq ---

check(
    'dnsmasq DHCPACK — ip, mac, hostname extracted',
    'Jun 10 12:30:00 dnsmasq-dhcp: DHCPACK(br0) 198.51.100.50 aa:bb:cc:dd:ee:ff laptop-01',
    **{'event.dataset': 'dhcp',
       'event.action': 'dhcpack',
       'source.ip': '198.51.100.50',
       'source.mac': 'AA-BB-CC-DD-EE-FF',
       'source.domain': 'laptop-01',
       'asus.dhcp.interface': 'br0'}
)

check(
    'dnsmasq DNS rebind warning — routes to dns not dhcp',
    'Jun 10 12:31:00 dnsmasq: possible DNS-rebind attack detected: example.local',
    **{'event.dataset': 'dns',
       'event.action': 'dnsmasq',
       'asus.dns.info': lambda v: v is not None}
)

# --- dropbear ---

check(
    'dropbear login success — user.name and source.ip extracted',
    'Jun 10 12:32:00 dropbear: Login succeeded for \'admin\' from 192.0.2.20:51000',
    **{'event.dataset': 'auth',
       'event.action': 'ssh-login',
       'event.outcome': 'success',
       'user.name': 'admin',
       'source.ip': '192.0.2.20',
       'source.port': 51000}
)

check(
    'dropbear bad password — outcome failure, user and ip extracted',
    'Jun 10 12:32:05 dropbear: Bad password attempt for \'admin\' from 203.0.113.9:51001',
    **{'event.outcome': 'failure',
       'user.name': 'admin',
       'source.ip': '203.0.113.9'}
)

# --- roamast / bsd ---

check(
    'roamast weak signal disconnect — dataset roaming',
    'Jun 10 12:33:02 roamast: wl1.2: disconnect weak signal strength station [aa:bb:cc:dd:ee:ff]',
    **{'event.dataset': 'roaming',
       'event.action': 'roaming-disconnect-weak-signal',
       'event.outcome': 'failure'}
)

check(
    'bsd BSS transition — structured roaming fields',
    'Jun 10 12:34:00 bsd: bsd: BSS Transit Response: ifname=wl1.2, event=1, token=2, status=0, mac=aa:bb:cc:dd:ee:ff',
    **{'event.dataset': 'roaming',
       'event.action': 'bss-transition',
       'asus.roaming.event_id': 1,
       'asus.roaming.token': 2,
       'asus.roaming.status_code': 0}
)

# --- system catch-all ---

check(
    'avahi-daemon — mdns dataset',
    'Jun 10 12:35:00 avahi-daemon: Registering new address record for 192.0.2.1 on br0.IPv4.',
    **{'event.dataset': 'mdns', 'category': 'network'}
)

check(
    'miniupnpd — upnp dataset',
    'Jun 10 12:35:01 miniupnpd: HTTP request from 198.51.100.30:5000',
    **{'event.dataset': 'upnp', 'category': 'network'}
)

check(
    'cfg_server — falls through to system catch-all without error',
    'Jun 10 12:05:48 cfg_server: after filter, available chanspec(bw2g:3 channel2g:1,2,3)',
    **{'event.dataset': 'system',
       'event.module': 'asus',
       'tags': lambda v: v is not None and 'asus' in v}
)

check(
    'unrecognized future daemon — safe catch-all, no exception',
    'Jun 10 12:37:00 some_future_daemon: a brand new message shape',
    **{'event.dataset': 'system', 'event.module': 'asus'}
)

check(
    'malformed line with no syslog header — does not raise exception',
    'this line has no syslog header structure whatsoever',
    **{'event.module': 'asus', 'tags': lambda v: v is not None}
)

# --- observer identification ---

check(
    'source IP 192.0.2.1 → GT-BE98-Pro',
    'Jun 10 12:05:43 kernel: ACCEPT IN=br0 OUT=eth0 SRC=198.51.100.1 DST=198.51.100.2',
    source_ip='192.0.2.1:514',
    **{'observer.name': 'GT-BE98-Pro'}
)

check(
    'source IP 192.0.2.2 → GT-AXE16000',
    'Jun 10 12:05:43 kernel: ACCEPT IN=br0 OUT=eth0 SRC=198.51.100.1 DST=198.51.100.2',
    source_ip='192.0.2.2:514',
    **{'observer.name': 'GT-AXE16000'}
)

# --- shared fields present on every event ---

check(
    'event.module always set to asus',
    'Jun 10 12:05:43 kernel: ACCEPT IN=br0 OUT=eth0 SRC=198.51.100.1 DST=198.51.100.2',
    **{'event.module': 'asus', 'event.kind': 'event'}
)

check(
    'asus tag always appended',
    'Jun 10 12:05:48 cfg_server: hello',
    **{'tags': lambda v: isinstance(v, list) and 'asus' in v}
)

check(
    '_tmp removed from final document',
    'Jun 10 12:05:43 kernel: ACCEPT IN=br0 OUT=eth0 SRC=198.51.100.1 DST=198.51.100.2',
    **{'_tmp': None}
)

# ---------------------------------------------------------------------------
# Optional bulk test (requires syslog.txt passed as CLI argument)
# ---------------------------------------------------------------------------

print()
if len(sys.argv) > 1:
    syslog_path = sys.argv[1]
    print(f'Bulk validation: {syslog_path}')
    total, counts, bad_pnames = run_bulk(syslog_path)
    print(f'  total lines processed : {total}')
    print(f'  dataset distribution  : {dict(counts)}')
    bulk_pass = True
    if None in counts:
        print(f'  FAIL: {counts[None]} lines with no event.dataset set')
        bulk_pass = False
    if bad_pnames:
        print(f'  FAIL: {len(bad_pnames)} lines where process.name looks like a wireless interface (original bug)')
        for line, pname in bad_pnames[:3]:
            print(f'    {pname!r} <- {line}')
        bulk_pass = False
    if bulk_pass:
        print(f'  PASS  bulk validation')
        PASS += 1
    else:
        FAIL += 1
else:
    print('Bulk validation skipped (pass path/to/syslog.txt as argument to enable).')

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print()
print('=' * 60)
print(f'Results: {PASS} passed, {FAIL} failed')
print('=' * 60)
sys.exit(0 if FAIL == 0 else 1)
