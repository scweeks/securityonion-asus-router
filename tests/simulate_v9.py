"""
simulate_v9.py — Python mirror of the ASUS router ingest pipeline (v9).

Faithfully mirrors the Elasticsearch Painless/grok logic so the pipeline
can be validated against real or synthetic log lines without a running
Elasticsearch instance. Used by run_tests.py and the GitHub Actions CI.

Grok primitives are derived from Elasticsearch's own ecs-v1/grok-patterns
source to ensure character-class fidelity.
"""

import re
from collections import Counter

# ---------------------------------------------------------------------------
# Grok primitives (verified against ES ecs-v1/grok-patterns)
# ---------------------------------------------------------------------------
PROG             = r'[\x21-\x5a\x5c\x5e-\x7e]+'
POSINT           = r'\b(?:[1-9][0-9]*)\b'
SYSLOGTIMESTAMP  = (r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)'
                    r' +(?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9])'
                    r' (?:2[0123]|[01]?[0-9]):(?:[0-5][0-9]):(?:[0-5][0-9])')
ASUSHOST         = r'[^\s:]+'   # custom: excludes colon to avoid absorbing program tags
COMMONMAC        = r'(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}'

HEADER_RE = re.compile(
    r'^(?:<(?P<pri>\d+)>)?(?P<ts>' + SYSLOGTIMESTAMP + r')\s+'
    r'(?:(?P<host>' + ASUSHOST + r')\s+)?'
    r'(?P<prog>' + PROG + r')(?:\[(?P<pid>' + POSINT + r')\])?:\s*(?P<body>.*)$'
)

SEV_NAMES = ["EMERG","ALERT","CRIT","ERR","WARN","NOTICE","INFO","DEBUG"]
FAC_NAMES = ["KERN","USER","MAIL","DAEMON","AUTH","SYSLOG","LPR","NEWS","UUCP","CRON",
             "AUTHPRIV","FTP","NTP","SECURITY","CONSOLE","SOLARIS-CRON",
             "LOCAL0","LOCAL1","LOCAL2","LOCAL3","LOCAL4","LOCAL5","LOCAL6","LOCAL7"]

# ---------------------------------------------------------------------------
# Document helper
# ---------------------------------------------------------------------------

class Doc(dict):
    """Thin dotted-path wrapper over a plain dict, mirroring ES ctx access."""

    def get_path(self, path, default=None):
        cur = self
        for part in path.split('.'):
            if not isinstance(cur, dict) or part not in cur:
                return default
            cur = cur[part]
        return cur

    def set_path(self, path, value):
        parts = path.split('.')
        cur = self
        for part in parts[:-1]:
            if part not in cur or not isinstance(cur[part], dict):
                cur[part] = {}
            cur = cur[part]
        cur[parts[-1]] = value

    def append_path(self, path, value, allow_dup=False):
        cur = self.get_path(path)
        if cur is None:
            cur = []
        if not allow_dup and value in cur:
            self.set_path(path, cur)
            return
        cur.append(value)
        self.set_path(path, cur)

# ---------------------------------------------------------------------------
# Entry pipeline
# ---------------------------------------------------------------------------

def entry_pipeline(message, source_ip):
    ctx = Doc()
    ctx['message'] = message
    ctx.set_path('log.source.address', source_ip)

    # --- shared identity ---
    ctx.set_path('event.module', 'asus')
    ctx.set_path('event.kind', 'event')

    # --- FIX: clear upstream syslog pipeline's default event.dataset ---
    # In production the upstream SO `syslog` pipeline sets event.dataset="syslog"
    # before calling us. All five dispatch conditions check ctx.event?.dataset == null,
    # so without this removal none of them would ever fire, leaving every event
    # as asus.syslog. This mirrors the remove processor in the asus entry pipeline.
    if isinstance(ctx.get('event'), dict) and 'dataset' in ctx.get('event', {}):
        del ctx['event']['dataset']

    # --- header grok ---
    m = HEADER_RE.match(message)
    if m and m.group('prog'):
        if m.group('pri') is not None:
            ctx.set_path('syslog.priority', int(m.group('pri')))
        ctx.set_path('syslog.timestamp', m.group('ts'))
        if m.group('host'):
            ctx.set_path('syslog.host', m.group('host'))
        ctx.set_path('process.name', m.group('prog'))
        if m.group('pid'):
            ctx.set_path('process.pid', int(m.group('pid')))
        ctx.set_path('_tmp.body', m.group('body'))
    else:
        ctx.set_path('_tmp.body', message)

    # --- hostname → host.name ---
    if ctx.get_path('syslog.host'):
        ctx.set_path('host.name', ctx.get_path('syslog.host'))

    # --- severity / facility ---
    pri = ctx.get_path('syslog.priority')
    if pri is not None:
        sev, fac = pri % 8, pri // 8
        ctx.set_path('syslog.severity', sev)
        ctx.set_path('syslog.severity_label', SEV_NAMES[sev])
        ctx.set_path('syslog.facility', fac)
        if 0 <= fac < len(FAC_NAMES):
            ctx.set_path('syslog.facility_label', FAC_NAMES[fac])
        ctx.set_path('log.syslog.priority', pri)
        ctx.set_path('log.syslog.severity.code', sev)
        ctx.set_path('log.syslog.severity.name', SEV_NAMES[sev])
        ctx.set_path('log.syslog.facility.code', fac)
        if 0 <= fac < len(FAC_NAMES):
            ctx.set_path('log.syslog.facility.name', FAC_NAMES[fac])

    # --- dispatch ---
    pname = ctx.get_path('process.name')
    body  = ctx.get_path('_tmp.body') or ''

    KERNEL_WIRELESS = ('WLC_SCB_', 'CFG80211-ERROR', 'not mesh client', 'not exist in UDB')
    is_kernel_wireless = (pname == 'kernel' and
                          (body.startswith('SBF:') or
                           any(mk in body for mk in KERNEL_WIRELESS)))

    if pname == 'kernel' and 'SRC=' in body and 'DST=' in body:
        asus_firewall(ctx)
    elif pname in ('hostapd', 'wlceventd', 'acsd', 'roamast', 'bsd') or is_kernel_wireless:
        asus_wireless(ctx)
    elif pname and pname.startswith('dnsmasq'):
        asus_dhcp(ctx)
    elif pname == 'dropbear':
        asus_auth(ctx)
    else:
        asus_system(ctx)

    # --- observer identification ---
    ip = source_ip.split(':')[0] if source_ip else None
    ctx.set_path('observer.vendor', 'ASUSTeK')
    if not ctx.get_path('observer.type'):
        ctx.set_path('observer.type', 'router')
    if ip == '192.0.2.1':
        ctx.set_path('observer.name', 'GT-BE98-Pro')
        ctx.set_path('observer.product', 'ROG Rapture GT-BE98 Pro')
    elif ip == '192.0.2.2':
        ctx.set_path('observer.name', 'GT-AXE16000')
        ctx.set_path('observer.product', 'ROG Rapture GT-AXE16000')

    # --- related.ip / related.user ---
    if ctx.get_path('source.ip'):
        ctx.append_path('related.ip', ctx.get_path('source.ip'))
    if ctx.get_path('destination.ip'):
        ctx.append_path('related.ip', ctx.get_path('destination.ip'))
    if ctx.get_path('user.name'):
        ctx.append_path('related.user', ctx.get_path('user.name'))

    # --- tags ---
    ctx.append_path('tags', 'asus')

    # --- cleanup ---
    ctx.pop('_tmp', None)
    return ctx

# ---------------------------------------------------------------------------
# Sub-pipelines
# ---------------------------------------------------------------------------

def asus_firewall(ctx):
    body = ctx.get_path('_tmp.body') or ''
    ctx.set_path('event.dataset', 'firewall')
    ctx.set_path('category', 'network')
    ctx.set_path('observer.type', 'firewall')
    ctx.set_path('event.provider', 'kernel')

    m = re.match(r'^(?:IPTables-(?P<act1>\w+):|(?P<act2>\w+))\s+(?P<rest>.*)$', body)
    rest = body
    action_raw = None
    if m:
        action_raw = m.group('act1') or m.group('act2')
        rest = m.group('rest')

    nf = {}
    tcp_flags = []
    ip_flags  = []
    for tok in rest.split(' '):
        if not tok:
            continue
        if '=' in tok:
            k, _, v = tok.partition('=')
            if k == 'LEN' and 'LEN' in nf:
                nf['L4_LEN'] = v
            else:
                nf[k] = v
        elif tok in ('SYN','ACK','FIN','RST','PSH','URG','ECE','CWR','NS'):
            tcp_flags.append(tok.lower())
        elif tok in ('DF','MF','CE'):
            ip_flags.append(tok.lower())

    act = (action_raw or '').lower()
    act = {'dropped': 'drop', 'accepted': 'accept', 'rejected': 'reject'}.get(act, act)
    if act:
        ctx.set_path('asus.firewall.action', act)
        ctx.set_path('event.action', act)
        if act == 'accept':
            ctx.set_path('event.type', ['connection', 'allowed'])
            ctx.set_path('event.outcome', 'success')
        elif act in ('drop', 'reject'):
            ctx.set_path('event.type', ['connection', 'denied'])
            ctx.set_path('event.outcome', 'failure')

    if nf.get('SRC'): ctx.set_path('source.ip', nf['SRC'])
    if nf.get('DST'): ctx.set_path('destination.ip', nf['DST'])
    try:
        if nf.get('SPT'): ctx.set_path('source.port', int(nf['SPT']))
    except ValueError: pass
    try:
        if nf.get('DPT'): ctx.set_path('destination.port', int(nf['DPT']))
    except ValueError: pass

    proto = nf.get('PROTO', '')
    protomap = {'1':'icmp','2':'igmp','6':'tcp','17':'udp','41':'ipv6',
                '47':'gre','50':'esp','51':'ah','58':'ipv6-icmp','132':'sctp'}
    if proto:
        p = protomap.get(proto.lower(), proto.lower())
        ctx.set_path('network.transport', p)
        ctx.set_path('network.protocol', p)

    sip = nf.get('SRC',''); dip = nf.get('DST','')
    if ':' in sip or ':' in dip:
        ctx.set_path('network.type', 'ipv6')
    elif sip or dip:
        ctx.set_path('network.type', 'ipv4')

    in_if  = nf.get('IN',  '')
    out_if = nf.get('OUT', '')
    if in_if:  ctx.set_path('observer.ingress.interface.name', in_if)
    if out_if: ctx.set_path('observer.egress.interface.name',  out_if)
    if in_if and out_if:
        ctx.set_path('network.direction', 'inbound' if in_if.startswith('eth') else 'outbound')
    elif in_if.startswith('eth'):
        ctx.set_path('network.direction', 'inbound')
    elif in_if:
        ctx.set_path('network.direction', 'outbound')

    mac = nf.get('MAC','')
    if len(mac) >= 41:
        ctx.set_path('destination.mac', mac[0:17].replace(':','-').upper())
        ctx.set_path('source.mac',      mac[18:35].replace(':','-').upper())
        ctx.set_path('asus.firewall.ethertype', mac[36:])

    for field, key, cast in [
        ('asus.firewall.packet_length', 'LEN',    int),
        ('asus.firewall.transport_length', 'L4_LEN', int),
        ('asus.firewall.ttl',          'TTL',    int),
        ('asus.firewall.tcp_window',   'WINDOW', int),
        ('asus.firewall.tos',          'TOS',    str),
        ('asus.firewall.precedence',   'PREC',   str),
        ('asus.firewall.ip_id',        'ID',     str),
        ('asus.firewall.mark',         'MARK',   str),
    ]:
        try:
            if nf.get(key): ctx.set_path(field, cast(nf[key]))
        except (ValueError, TypeError): pass

    if tcp_flags: ctx.set_path('asus.firewall.tcp_flags', tcp_flags)
    if ip_flags:  ctx.set_path('asus.firewall.ip_flags',  ip_flags)

    # community_id is not simulated (requires C library); placeholder field
    ctx.set_path('_tmp.community_id_needed', True)


def asus_wireless(ctx):
    pname = ctx.get_path('process.name')
    body  = ctx.get_path('_tmp.body') or ''
    ctx.set_path('event.dataset', 'wireless')
    ctx.set_path('category', 'network')
    ctx.set_path('event.provider', pname)

    if pname == 'wlceventd':
        mm = re.match(
            r'^wlceventd_proc_event\((\d+)\):\s+(\S+):\s+(\S+)\s+(' + COMMONMAC + r'),'
            r'\s+status:\s+([^,]+)(?:,\s+reason:\s+([^,]+))?(?:,\s+rssi:(-?\d+))?',
            body)
        if mm:
            eid, iface, raw_action, mac, status, reason, rssi = mm.groups()
            ctx.set_path('asus.wireless.event_id', int(eid))
            ctx.set_path('asus.wireless.interface', iface)
            ctx.set_path('source.mac', mac.replace(':','-').upper())
            ctx.set_path('asus.wireless.status', status.strip())
            if reason: ctx.set_path('asus.wireless.reason', reason.strip())
            if rssi:   ctx.set_path('asus.wireless.rssi', int(rssi))
            norm = raw_action.lower().replace(' ', '_')
            ctx.set_path('event.action', 'wireless-' + norm)
            if norm.startswith('deauth') or norm.startswith('disassoc'):
                ctx.set_path('event.type', ['connection', 'end'])
                ctx.set_path('event.outcome', 'failure')
            elif norm in ('auth',) or norm.startswith('assoc') or norm.startswith('reassoc'):
                ctx.set_path('event.type', ['connection', 'start'])
                st = (status or '').lower()
                if 'successful' in st or st.strip() == '0' or '(0)' in st:
                    ctx.set_path('event.outcome', 'success')

    elif pname == 'hostapd':
        # Try channel-switch shape first (most specific)
        mm = re.match(r'^(\S+):\s+IEEE\s+(\S+)\s+driver had channel switch:\s+(.*)$', body)
        if mm:
            ctx.set_path('asus.wireless.interface', mm.group(1))
            ctx.set_path('asus.wireless.protocol',  mm.group(2))
            ctx.set_path('asus.wireless.info',       mm.group(3))
            ctx.set_path('event.action', 'wireless-channel-switch')
            ctx.set_path('event.type',   ['change', 'info'])
            ctx.set_path('event.outcome','success')
        else:
            # STA lines: try security-protocol form first ("WPA:"), then plain form
            # The plain form handles "IEEE 802.11: associated" where %{WORD}: fails
            # because "802.11" contains a dot and is preceded by a space.
            mm2 = re.match(r'^(\S+):\s+STA\s+(' + COMMONMAC + r')\s+(\w+):\s+(.*)$', body)
            if mm2:
                ctx.set_path('asus.wireless.interface',        mm2.group(1))
                ctx.set_path('source.mac', mm2.group(2).replace(':','-').upper())
                ctx.set_path('asus.wireless.security_protocol', mm2.group(3))
                info = mm2.group(4)
            else:
                mm3 = re.match(r'^(\S+):\s+STA\s+(' + COMMONMAC + r')\s+(.*)$', body)
                if mm3:
                    ctx.set_path('asus.wireless.interface', mm3.group(1))
                    ctx.set_path('source.mac', mm3.group(2).replace(':','-').upper())
                    info = mm3.group(3)
                else:
                    info = body
            ctx.set_path('asus.wireless.info', info)
            low = info.lower()
            if 'associated' in low and 'disassociated' not in low and 'deauthenticated' not in low:
                ctx.set_path('event.action', 'wireless-associated')
                ctx.set_path('event.type',   ['connection', 'start'])
                ctx.set_path('event.outcome','success')
            elif 'disassociated' in low:
                ctx.set_path('event.action', 'wireless-disassociated')
                ctx.set_path('event.type',   ['connection', 'end'])
                ctx.set_path('event.outcome','failure')
            elif 'deauthenticated' in low:
                ctx.set_path('event.action', 'wireless-deauthenticated')
                ctx.set_path('event.type',   ['connection', 'end'])
                ctx.set_path('event.outcome','failure')
            elif 'pairwise key handshake completed' in low:
                ctx.set_path('event.action', 'wireless-wpa-pairwise-key-handshake-completed')
                ctx.set_path('event.type',   ['connection', 'info'])
                ctx.set_path('event.outcome','success')
            elif 'group key handshake completed' in low:
                ctx.set_path('event.action', 'wireless-wpa-group-key-handshake-completed')
                ctx.set_path('event.type',   ['connection', 'info'])
                ctx.set_path('event.outcome','success')
            elif 'starting accounting session' in low:
                ctx.set_path('event.action', 'wireless-radius-accounting-start')
                ctx.set_path('event.type',   ['connection', 'info'])
                ctx.set_path('event.outcome','success')
            else:
                ctx.set_path('event.action', 'wireless-hostapd')
                ctx.set_path('event.type',   ['info'])
    elif pname == 'acsd':
        ctx.set_path('asus.wireless.info', body)
        ctx.set_path('event.action', 'wireless-channel-selection')
        ctx.set_path('event.type', ['change', 'info'])

    elif pname == 'roamast':
        ctx.set_path('event.dataset', 'roaming')
        low = body.lower()
        mm_mac = re.search(COMMONMAC, body)
        if mm_mac:
            ctx.set_path('source.mac', mm_mac.group(0).replace(':','-').upper())
        if 'disconnect weak signal' in low:
            ctx.set_path('event.action', 'roaming-disconnect-weak-signal')
            ctx.set_path('event.type', ['connection', 'end'])
            ctx.set_path('event.outcome', 'failure')
        elif 'deauth old sta' in low:
            ctx.set_path('event.action', 'roaming-deauth-old-station')
            ctx.set_path('event.type', ['connection', 'end'])
            ctx.set_path('event.outcome', 'success')
        elif 'determine candidate node' in low:
            ctx.set_path('event.action', 'roaming-candidate-selected')
            ctx.set_path('event.type', ['info'])
        elif 'remove client' in low:
            ctx.set_path('event.action', 'roaming-remove-client-monitor')
            ctx.set_path('event.type', ['info'])
        elif 'roam a client' in low:
            ctx.set_path('event.action', 'roaming-client')
            ctx.set_path('event.type', ['change'])
        else:
            ctx.set_path('event.action', 'roaming')
            ctx.set_path('event.type', ['info'])

    elif pname == 'bsd':
        ctx.set_path('event.dataset', 'roaming')
        mm = re.match(
            r'^bsd:\s+BSS Transit Response:\s+ifname=(\S+),\s+event=(\d+),\s+token=(\d+),'
            r'\s+status=(\d+),\s+mac=(' + COMMONMAC + r')', body)
        if mm:
            ctx.set_path('asus.wireless.interface', mm.group(1))
            ctx.set_path('asus.roaming.event_id',   int(mm.group(2)))
            ctx.set_path('asus.roaming.token',       int(mm.group(3)))
            ctx.set_path('asus.roaming.status_code', int(mm.group(4)))
            ctx.set_path('source.mac', mm.group(5).replace(':','-').upper())
        ctx.set_path('event.action', 'bss-transition')
        ctx.set_path('event.type', ['info'])

    elif pname == 'kernel':
        mac_m = re.search(COMMONMAC, body)
        if mac_m:
            ctx.set_path('source.mac', mac_m.group(0).replace(':','-').upper())
        if body.startswith('SBF:'):
            mm = re.match(
                r'^SBF:\s+(\w+):\s+INIT\s+\[(' + COMMONMAC + r')\]\s+'
                r'ID\s+(\d+)\s+BFW\s+(\d+)\s+THRSH\s+(\d+)', body)
            if mm:
                ctx.set_path('asus.wireless.driver',        mm.group(1))
                ctx.set_path('source.mac', mm.group(2).replace(':','-').upper())
                ctx.set_path('asus.wireless.sbf_id',        int(mm.group(3)))
                ctx.set_path('asus.wireless.sbf_bfw',       int(mm.group(4)))
                ctx.set_path('asus.wireless.sbf_threshold', int(mm.group(5)))
            ctx.set_path('event.action', 'wireless-sbf-init')
            ctx.set_path('event.type', ['info'])
        elif 'not mesh client' in body:
            ctx.set_path('event.action', 'wireless-mesh-client-operation-failed')
            ctx.set_path('event.type', ['info'])
            ctx.set_path('event.outcome', 'failure')
        elif 'not exist in UDB' in body:
            ctx.set_path('event.action', 'wireless-udb-client-operation-failed')
            ctx.set_path('event.type', ['info'])
            ctx.set_path('event.outcome', 'failure')
        elif 'WLC_SCB_DEAUTHORIZE' in body:
            ctx.set_path('event.action', 'wireless-kernel-deauthorize-error')
            ctx.set_path('event.type', ['connection', 'end'])
            ctx.set_path('event.outcome', 'failure')
        elif 'WLC_SCB_DEAUTHENTICATE_FOR_REASON' in body:
            ctx.set_path('event.action', 'wireless-kernel-deauthenticate-error')
            ctx.set_path('event.type', ['connection', 'end'])
            ctx.set_path('event.outcome', 'failure')
        elif 'CFG80211-ERROR' in body:
            ctx.set_path('event.action', 'wireless-cfg80211-error')
            ctx.set_path('event.type', ['info'])
            ctx.set_path('event.outcome', 'failure')
        else:
            ctx.set_path('event.action', 'wireless-kernel')
            ctx.set_path('event.type', ['info'])


def asus_dhcp(ctx):
    body  = ctx.get_path('_tmp.body') or ''
    pname = ctx.get_path('process.name')
    ctx.set_path('event.provider', pname)
    ctx.set_path('category', 'network')

    mm = re.match(r'^(\w+)\((\S+)\)\s+(\d+\.\d+\.\d+\.\d+)\s+(' + COMMONMAC + r')(?:\s+(.+))?$', body)
    if mm:
        ctx.set_path('event.dataset', 'dhcp')
        ctx.set_path('event.action', mm.group(1).lower())
        ctx.set_path('asus.dhcp.interface', mm.group(2))
        ctx.set_path('source.ip',  mm.group(3))
        ctx.set_path('source.mac', mm.group(4).replace(':','-').upper())
        if mm.group(5):
            ctx.set_path('source.domain', mm.group(5).strip())
    else:
        ctx.set_path('event.dataset', 'dns')
        ctx.set_path('event.action', 'dnsmasq')
        ctx.set_path('event.type', ['info'])
        ctx.set_path('asus.dns.info', body)


def asus_auth(ctx):
    body = ctx.get_path('_tmp.body') or ''
    ctx.set_path('event.dataset', 'auth')
    ctx.set_path('category', 'authentication')
    ctx.set_path('event.provider', 'dropbear')

    # FIX: actual Dropbear format is "Login succeeded for" not "<word> auth succeeded for"
    mm = re.match(r"^Login succeeded for '([^']+)' from (\d+\.\d+\.\d+\.\d+):(\d+)", body)
    if mm:
        ctx.set_path('user.name', mm.group(1))
        ctx.set_path('source.ip', mm.group(2))
        ctx.set_path('source.port', int(mm.group(3)))
    else:
        mm = re.search(r"for '([^']+)'", body)
        if mm: ctx.set_path('user.name', mm.group(1))
        mm2 = re.search(r'from (\d+\.\d+\.\d+\.\d+):(\d+)', body)
        if mm2:
            ctx.set_path('source.ip', mm2.group(1))
            ctx.set_path('source.port', int(mm2.group(2)))

    if 'succeeded' in body:
        ctx.set_path('event.type', ['start'])
        ctx.set_path('event.outcome', 'success')
        ctx.set_path('event.action', 'ssh-login')
    elif 'Bad password' in body or 'nonexistent user' in body:
        ctx.set_path('event.type', ['start'])
        ctx.set_path('event.outcome', 'failure')
        ctx.set_path('event.action', 'ssh-login')


def asus_system(ctx):
    pname = ctx.get_path('process.name')
    body  = ctx.get_path('_tmp.body') or ''
    ctx.set_path('event.provider', pname)

    if pname == 'avahi-daemon':
        ctx.set_path('event.dataset', 'mdns')
        ctx.set_path('category', 'network')
        ctx.set_path('event.action', 'mdns')
        ctx.set_path('event.type', ['info'])
    elif pname == 'miniupnpd':
        ctx.set_path('event.dataset', 'upnp')
        ctx.set_path('category', 'network')
        ctx.set_path('event.action', 'upnp-event')
        ctx.set_path('event.type', ['info'])
        ctx.set_path('asus.upnp.info', body)
    elif pname == 'kernel':
        if 'usbcore:' in body:
            ctx.set_path('event.dataset', 'usb')
            ctx.set_path('category', 'host')
            ctx.set_path('event.action', 'usb')
            ctx.set_path('event.type', ['info'])
        elif ' entered ' in body and ' state' in body:
            mm = re.match(r'^(\S+):\s+port\s+(\d+)\((\S+)\)\s+entered\s+(\w+)\s+state', body)
            if mm:
                ctx.set_path('asus.network.bridge',    mm.group(1))
                ctx.set_path('asus.network.port',      int(mm.group(2)))
                ctx.set_path('asus.network.interface', mm.group(3))
                ctx.set_path('asus.network.state',     mm.group(4))
            ctx.set_path('event.dataset', 'network')
            ctx.set_path('category', 'network')
            ctx.set_path('event.action', 'bridge-port-state')
            ctx.set_path('event.type', ['change'])
        else:
            low = body.lower()
            # FIX: use startsWith('x') equivalent — b[0]=='x' causes char cast error in Painless
            is_crash = (
                'fatal signal' in low or
                body.startswith('===DDD===') or
                body.startswith('CPU:') or
                body.startswith('Hardware name:') or
                body.startswith('pc :') or
                body.startswith('lr :') or
                body.startswith('sp :') or
                body.startswith('pstate:') or
                (len(body) > 2 and body.startswith('x') and ':' in body[1:4]) or
                (' - ' in body and ', [' in body and body.endswith(']'))
            )
            if is_crash:
                ctx.set_path('event.dataset', 'kernel')
                ctx.set_path('category', 'host')
                ctx.set_path('event.action',
                             'kernel-fatal-signal' if 'fatal signal' in low else 'kernel-crash-dump')
                ctx.set_path('event.type', ['info'])
                if 'fatal signal' in low:
                    ctx.set_path('event.outcome', 'failure')
            else:
                ctx.set_path('event.dataset', 'system')
                ctx.set_path('category', 'host')
                ctx.set_path('event.action', 'kernel-message')
                ctx.set_path('event.type', ['info'])
    else:
        ctx.set_path('event.dataset', 'system')
        ctx.set_path('category', 'host')
        ctx.set_path('event.action', 'system')
        ctx.set_path('event.type', ['info'])


# ---------------------------------------------------------------------------
# Bulk test helper (used by run_tests.py when syslog.txt is available)
# ---------------------------------------------------------------------------

def run_bulk(path, source_ip='192.0.2.1:514'):
    counts = Counter()
    bad_pnames = []
    total = 0
    with open(path) as f:
        for line in f:
            line = line.rstrip('\n')
            if not line.strip():
                continue
            total += 1
            ctx = entry_pipeline(line, source_ip)
            ds = ctx.get_path('event.dataset')
            counts[ds] += 1
            pname = ctx.get_path('process.name')
            if pname and re.match(r'^wl\d+(\.\d+)?$', pname):
                bad_pnames.append((line[:80], pname))
    return total, counts, bad_pnames
