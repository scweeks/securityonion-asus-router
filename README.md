# securityonion-asus-router

[![CI](https://github.com/scweeks/securityonion-asus-router/actions/workflows/validate.yml/badge.svg)](https://github.com/scweeks/securityonion-asus-router/actions/workflows/validate.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security Onion](https://img.shields.io/badge/Security%20Onion-3.1-blue.svg)](https://securityonion.net/)
[![Python 3](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/)

Elasticsearch ingest pipeline for ASUS ROG router syslog in Security Onion 3.1.

Correctly parses and classifies every log shape produced by ASUS ROG routers
into structured ECS fields, covering firewall (netfilter), wireless association,
DHCP, SSH authentication, AiMesh roaming, and system events across all daemons
the firmware generates.

## Tested on

| Component | Details |
|---|---|
| Security Onion | 3.1 |
| Elasticsearch | 9.3.3 |
| Hardware | ASUS ROG Rapture GT-BE98 Pro + GT-AXE16000 (AiMesh) |

Should work with any ASUS router running stock firmware that sends syslog over
UDP 514. The pipeline recognizes daemon names (`kernel`, `hostapd`, `wlceventd`,
`dnsmasq`, `dropbear`, `roamast`, `bsd`, `avahi-daemon`, `miniupnpd`, `acsd`)
rather than specific router models, so it is not hardware-specific.

---

## Table of contents

- [Architecture](#architecture)
- [Datasets produced](#datasets-produced)
- [ECS fields reference](#ecs-fields-reference)
- [Configuration](#configuration)
- [Router syslog setup](#router-syslog-setup)
- [Installation](#installation)
- [Updating pipelines](#updating-pipelines-no-restart-needed)
- [SOUP updates](#soup-updates)
- [Searching in Hunt](#searching-in-hunt)
- [Running the tests](#running-the-tests)
- [Known limitations](#known-limitations)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

---

## Architecture

Six Elasticsearch ingest pipelines work together:

```
SO syslog pipeline (platform)
  └─► asus               (entry/dispatcher — this repo)
        ├─► asus.firewall    kernel netfilter ACCEPT/DROP/REJECT
        ├─► asus.wireless    hostapd, wlceventd, acsd, roamast, bsd,
        │                    kernel wireless driver errors (SBF/WLC_SCB_/CFG80211)
        ├─► asus.dhcp        dnsmasq DHCP and DNS
        ├─► asus.auth        dropbear SSH
        └─► asus.system      avahi-daemon, miniupnpd, remaining kernel, catch-all
              └─► common     (platform — GeoIP, ASN, finalize)
```

The `asus` entry pipeline keeps that exact name so the routing rule you add to
the platform's `ingest/syslog` file routes correctly without any further changes
after initial setup.

## Datasets produced

| `event.dataset` | Source daemons / message types |
|---|---|
| `asus.firewall` | kernel netfilter ACCEPT/DROP/REJECT |
| `asus.wireless` | hostapd, wlceventd, acsd, kernel SBF/WLC\_SCB\_/CFG80211 |
| `asus.roaming` | roamast, bsd (AiMesh BSS transitions) |
| `asus.dhcp` | dnsmasq-dhcp lease events |
| `asus.dns` | dnsmasq DNS warnings (rebind, etc.) |
| `asus.auth` | dropbear SSH login/failure |
| `asus.mdns` | avahi-daemon |
| `asus.upnp` | miniupnpd |
| `asus.network` | kernel bridge port state changes |
| `asus.usb` | kernel USB device events |
| `asus.kernel` | kernel crash dumps / fatal signals |
| `asus.system` | catch-all for unrecognized daemons (e.g. cfg\_server) |

## ECS fields reference

Key fields populated per dataset. All datasets also receive `event.module`,
`event.kind`, `event.provider`, `observer.*`, `syslog.*`, `@timestamp`,
and `tags: [asus]`.

### asus.firewall

| Field | Example | Notes |
|---|---|---|
| `event.action` | `accept` / `drop` / `reject` | |
| `event.outcome` | `success` / `failure` | |
| `event.type` | `[connection, allowed]` | |
| `source.ip` | | |
| `source.port` | | |
| `source.mac` | `AA-BB-CC-DD-EE-FF` | normalized to dash-separated uppercase |
| `destination.ip` | | |
| `destination.port` | | |
| `destination.mac` | | |
| `network.transport` | `tcp` / `udp` / `icmp` | |
| `network.direction` | `inbound` / `outbound` | |
| `network.community_id` | | Elasticsearch community\_id processor |
| `observer.type` | `firewall` | overridden here only |
| `observer.ingress.interface.name` | `eth0` | |
| `observer.egress.interface.name` | `br0` | |
| `asus.firewall.action` | | raw netfilter action |
| `asus.firewall.ttl` | | |
| `asus.firewall.tcp_flags` | `[syn, ack]` | |
| `related.ip` | | source + destination IPs |

### asus.wireless / asus.roaming

| Field | Example | Notes |
|---|---|---|
| `event.action` | `wireless-associated` | |
| `event.outcome` | `success` / `failure` | |
| `source.mac` | `AA-BB-CC-DD-EE-FF` | station MAC |
| `asus.wireless.interface` | `wl1.2` | radio interface |
| `asus.wireless.status` | `Successful (0)` | wlceventd |
| `asus.wireless.rssi` | `-47` | wlceventd, dBm |
| `asus.wireless.reason` | `Unspecified reason (1)` | deauth reason |
| `asus.wireless.driver` | `dhd0` | kernel SBF messages |
| `asus.roaming.event_id` | | bsd BSS transition |
| `asus.roaming.status_code` | | |

### asus.dhcp

| Field | Example | Notes |
|---|---|---|
| `event.action` | `dhcpack` / `dhcprequest` | normalized lowercase |
| `source.ip` | | assigned IP |
| `source.mac` | | client MAC |
| `source.domain` | `laptop-01` | hostname if provided |
| `asus.dhcp.interface` | `br0` | |

### asus.auth

| Field | Example | Notes |
|---|---|---|
| `event.action` | `ssh-login` | |
| `event.outcome` | `success` / `failure` | |
| `user.name` | `admin` | |
| `source.ip` | | connecting client |
| `source.port` | | |
| `related.user` | | |

---

## Configuration

Two places require your environment-specific values before deploying.

### 1. Routing rule in `ingest/syslog`

See [Installation step 2](#2-add-the-routing-rule-to-your-local-syslog-pipeline).
Replace the example IP addresses with your actual router IPs.

### 2. Observer identification in `pipelines/asus`

The observer script maps source IP to router name and model. Open
`pipelines/asus` and find the Painless script under the `"Identify which
physical router"` description. Replace the placeholder IPs, hostnames, and
model names with your own:

```javascript
if ('192.0.2.1'.equals(ip)) {             // ← your primary router IP
    ctx.observer.put('name', 'my-router-1');             // ← your router hostname
    ctx.observer.put('product', 'ASUS ROG Rapture XYZ'); // ← your router model
} else if ('192.0.2.2'.equals(ip)) {      // ← your secondary router IP
    ctx.observer.put('name', 'my-router-2');             // ← your router hostname
    ctx.observer.put('product', 'ASUS ROG Rapture XYZ'); // ← your router model
}
```

Add or remove `else if` blocks for however many routers you have.

### 3. Timezone

The `date` processor in `pipelines/asus` is set to `America/New_York`. If your
routers are in a different timezone, update this value before deploying:

```json
"timezone": "America/New_York"
```

ASUS routers log in local time with no timezone in the BSD syslog timestamp.
Getting this wrong will cause `@timestamp` to be off by the difference between
your timezone and Eastern Time.

> All IP addresses in the pipeline files and test harness use RFC 5737 reserved
> documentation addresses (`192.0.2.x`, `198.51.100.x`). They are not real
> addresses and must be replaced with your actual values before use.

---

## Router syslog setup

Your ASUS router must be configured to send syslog to your Security Onion
manager before this pipeline does anything useful. Steps apply to stock ASUS
firmware (the UI may vary slightly by model and firmware version):

1. Log into your router admin panel (typically `http://192.168.x.1`)
2. Navigate to **Administration → System**
3. Scroll to the **System Log** section
4. Set **Enable System Log** to **Yes**
5. Set **Log server IP address** to your Security Onion manager's IP
6. Set **Log server port** to `514`
7. Set **Protocol** to `UDP`
8. Click **Apply**

Repeat for each router. In an AiMesh setup, configure syslog on each node
individually — each node sends its own syslog stream independently.

To verify logs are arriving before deploying this parser, SSH into your SO
manager and run:

```bash
sudo tcpdump -i any -n udp port 514 -c 20
```

You should see packets from your router IPs within a few seconds.

---

## Installation

### Requirements

- Security Onion 3.1 standalone or distributed
- Routers sending syslog (UDP 514) to the SO manager (see [Router syslog setup](#router-syslog-setup))
- Python 3 (for running the test harness locally — not required on the SO server)

### 1. Clone this repository

```bash
git clone https://github.com/scweeks/securityonion-asus-router.git
cd securityonion-asus-router
```

### 2. Edit configuration values

Before copying any files to your server, make the two configuration edits
described in the [Configuration](#configuration) section — your router IPs,
hostnames/model names in `pipelines/asus`, and your timezone.

### 3. Run the tests

Confirm the pipeline logic is intact before deploying:

```bash
python3 tests/run_tests.py
```

All 30 tests must pass.

### 4. Copy the pipeline files to the local salt directory

```bash
sudo cp pipelines/asus \
        pipelines/asus.firewall \
        pipelines/asus.wireless \
        pipelines/asus.dhcp \
        pipelines/asus.auth \
        pipelines/asus.system \
    /opt/so/saltstack/local/salt/elasticsearch/files/ingest/
```

Filenames must match exactly — no extensions.

### 5. Add the routing rule to your local syslog pipeline

Create a local copy of the platform syslog pipeline if one doesn't exist:

```bash
sudo cp /opt/so/saltstack/default/salt/elasticsearch/files/ingest/syslog \
        /opt/so/saltstack/local/salt/elasticsearch/files/ingest/syslog
```

Open the file and add this block **before** the `common` pipeline processor,
replacing `192.0.2.1` and `192.0.2.2` with your actual router IPs:

```json
{
  "pipeline": {
    "name": "asus",
    "ignore_failure": true,
    "if": "ctx.log?.source?.address != null && (ctx.log.source.address == '192.0.2.1' || ctx.log.source.address == '192.0.2.2' || ctx.log.source.address.toString().startsWith('192.0.2.1:') || ctx.log.source.address.toString().startsWith('192.0.2.2:'))"
  }
}
```

### 6. Register the pipelines

The first time, restart Elasticsearch to let salt register all six files:

```bash
sudo so-elasticsearch-restart
```

> **Note:** This restart can take several minutes on home-lab hardware. See
> [Troubleshooting](#troubleshooting) if it hangs.

### 7. Verify

In Kibana Dev Tools, confirm all six pipelines registered:

```
GET _ingest/pipeline/asus*
```

Then test with a simulated document, replacing `192.0.2.2` with one of your
actual router IPs:

```
POST _ingest/pipeline/asus/_simulate
{
  "docs": [
    {
      "_source": {
        "log": { "source": { "address": "192.0.2.2:514" } },
        "message": "Jun 10 12:06:18 hostapd: wl1.2: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated"
      }
    }
  ]
}
```

Expected result: `process.name: "hostapd"`, `event.dataset: "wireless"`,
`event.action: "wireless-associated"`, `source.mac: "AA-BB-CC-DD-EE-FF"`.

---

## Updating pipelines (no restart needed)

Once Elasticsearch is running, pipeline changes take effect immediately via
the REST API — **no `so-elasticsearch-restart` required**:

In Kibana Dev Tools:

```
PUT _ingest/pipeline/asus.wireless
{ ...updated file contents... }
```

Also update the file on disk so salt doesn't overwrite your change on the
next restart:

```bash
sudo cp pipelines/asus.wireless \
    /opt/so/saltstack/local/salt/elasticsearch/files/ingest/asus.wireless
```

`so-elasticsearch-restart` is only needed for container-level changes — heap
size, TLS config, network bind address — not for ingest pipeline updates.

---

## SOUP updates

Security Onion updates (`soup`) do not overwrite files in the `local` salt
tree. Your pipeline files are safe across SOUP updates as long as they live
in `/opt/so/saltstack/local/salt/elasticsearch/files/ingest/`, not in the
default path.

After a major SOUP update, check the platform's own `syslog` pipeline for
changes:

```bash
diff /opt/so/saltstack/default/salt/elasticsearch/files/ingest/syslog \
     /opt/so/saltstack/local/salt/elasticsearch/files/ingest/syslog
```

If the default changed in a way that affects the dispatch order or upstream
field names, you may need to update your local copy accordingly.

---

## Searching in Hunt

Show all router traffic grouped by dataset:

```
event.module:"asus" | groupby event.dataset
```

`event.module: "asus"` is set as the first step of the entry pipeline on
every event regardless of dataset, making it the most reliable anchor for
finding all router traffic.

Useful follow-on queries:

```
event.dataset:"asus.firewall" AND event.action:"drop"
event.dataset:"asus.auth" AND event.outcome:"failure"
event.dataset:"asus.wireless" AND event.action:"wireless-deauthenticated"
event.dataset:"asus.dhcp" | groupby source.mac
```

---

## Running the tests

Requires Python 3 only — no external dependencies.

Synthetic test suite (runs in CI and locally):

```bash
python3 tests/run_tests.py
```

With bulk validation against a real syslog capture (not included in this
repo — see [Known limitations](#known-limitations)):

```bash
python3 tests/run_tests.py /path/to/syslog.txt
```

The bulk pass confirms zero lines produce no `event.dataset` and zero lines
end up with a wireless interface name in `process.name` (the original bug).

---

## Known limitations

**Timezone is hardcoded.** The `date` processor in `pipelines/asus` is set to
`America/New_York`. Users in other timezones must change this before deploying
or `@timestamp` will be incorrect. See [Configuration](#configuration).

**No retroactive reclassification.** Events indexed before this pipeline was
deployed (or before a pipeline update) are not reclassified. Only new events
flowing through after deployment are parsed correctly. Correcting historical
data requires a reindex operation.

**Bulk test requires your own capture.** The test harness's bulk validation
mode expects a real syslog capture passed as a CLI argument. No capture file
is included in this repo — real log data can contain sensitive network
information. See [.gitignore](.gitignore).

**`community_id` not simulated in the test harness.** The Python simulator
does not compute `network.community_id` (it requires native libraries).
This field is correctly populated by Elasticsearch's built-in `community_id`
processor in production.

**AiMesh node traffic.** In AiMesh configurations, wireless events
(association, roaming) may be logged by the node the client is currently
connected to, not the primary router. The `observer.name` field will reflect
whichever device's source IP the log arrived from.

---

## Troubleshooting

### `so-elasticsearch-restart` hangs

This is a known pattern on home-lab hardware, unrelated to the pipeline files.
Open a second terminal while the command is running:

```bash
# Is Elasticsearch up?
sudo so-elasticsearch-query _cluster/health?pretty

# What is the container doing?
sudo docker logs so-elasticsearch --tail 100 -f

# Is it just slow shard recovery? (check for active log output)
# If logs show shard recovery in progress — just wait, can take 15+ min.
# If logs are completely silent for several minutes:
sudo docker ps -a | grep elasticsearch   # container should appear
```

If the restart is genuinely stuck with no container present:

```bash
sudo pkill -f so-elasticsearch-restart
sudo rm -f /var/cache/salt/minion/proc/*
sudo salt-call state.apply elasticsearch
```

### Only some pipelines registered after restart

Salt applies files alphabetically and stops if Elasticsearch doesn't come up
in time. Check which are missing:

```
GET _ingest/pipeline/asus*
```

For any missing pipelines, register them directly via Dev Tools — **no restart
needed**:

```
PUT _ingest/pipeline/asus.wireless
{ ...file contents... }
```

### All events landing in `asus.syslog`

The upstream SO `syslog` pipeline sets `event.dataset: "syslog"` before
calling the `asus` pipeline. The `asus` entry pipeline removes this value
immediately so dispatch works correctly. If you see `asus.syslog` for all
events, the version of `pipelines/asus` on disk is likely stale — confirm the
file contains a `remove` processor for `event.dataset` as the third processor:

```bash
python3 -c "
import json
with open('/opt/so/saltstack/local/salt/elasticsearch/files/ingest/asus') as f:
    d = json.load(f)
print(list(d['processors'][2].keys())[0])  # should print: remove
"
```

### Simulate tests show missing fields

If `GET _ingest/pipeline/asus*` shows all six pipelines but simulate output is
missing fields like `event.dataset`, run the simulate with `"verbose": true`
to see exactly where the chain stops:

```
POST _ingest/pipeline/asus/_simulate
{
  "verbose": true,
  "docs": [{ "_source": { ... } }]
}
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Design notes

See [DESIGN.md](DESIGN.md) for the root-cause analysis of the v1–v8
`process.name` bug, why the header grok is written the way it is, and why
`event.dataset` is explicitly removed at the start of the entry pipeline.

## License

[MIT](LICENSE)
