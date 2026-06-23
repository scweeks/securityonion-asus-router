# securityonion-asus-router

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

## Requirements

- Security Onion 3.1 standalone or distributed
- Routers sending syslog (UDP 514) to the SO manager
- The six pipeline files installed in the SO local salt ingest directory (see below)

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

The `asus` pipeline keeps that exact name so the routing rule in the platform's
`ingest/syslog` file needs no changes.

## Datasets produced

| `event.dataset` | Source daemons / message types |
|---|---|
| `asus.firewall` | kernel netfilter ACCEPT/DROP/REJECT |
| `asus.wireless` | hostapd, wlceventd, acsd, kernel SBF/WLC_SCB_/CFG80211 |
| `asus.roaming` | roamast, bsd (AiMesh BSS transitions) |
| `asus.dhcp` | dnsmasq-dhcp lease events |
| `asus.dns` | dnsmasq DNS warnings (rebind, etc.) |
| `asus.auth` | dropbear SSH login/failure |
| `asus.mdns` | avahi-daemon |
| `asus.upnp` | miniupnpd |
| `asus.network` | kernel bridge port state changes |
| `asus.usb` | kernel USB device events |
| `asus.kernel` | kernel crash dumps / fatal signals |
| `asus.system` | catch-all for unrecognized daemons (e.g. cfg_server) |


## Configuration

Two places require your environment-specific values before deploying:

**1. Routing rule in `ingest/syslog`** (see Installation step 2) — replace the
example IP addresses with your actual router IPs.

**2. Observer identification in `pipelines/asus`** — the observer script maps
source IP to router name and model. Find this section in the Painless script
and replace the placeholder IPs, hostnames, and model names with your own:

```javascript
if ('192.0.2.1'.equals(ip)) {             // ← your primary router IP
    ctx.observer.put('name', 'my-router-1');           // ← your router hostname
    ctx.observer.put('product', 'ASUS ROG Rapture XYZ'); // ← your router model
} else if ('192.0.2.2'.equals(ip)) {      // ← your secondary router IP (remove if only one)
    ctx.observer.put('name', 'my-router-2');           // ← your router hostname
    ctx.observer.put('product', 'ASUS ROG Rapture XYZ'); // ← your router model
}
```

Add or remove `else if` blocks to match however many routers you have.

All IP addresses in the pipeline files and test harness use RFC 5737 reserved
documentation addresses (`192.0.2.x`, `198.51.100.x`) — they are not real
addresses and must be replaced with your actual values before use.

## Installation

### 1. Copy the pipeline files to the local salt directory

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

### 2. Add the routing rule to your local syslog pipeline

Edit (or create) your local copy of the syslog pipeline:

```bash
sudo cp /opt/so/saltstack/default/salt/elasticsearch/files/ingest/syslog \
        /opt/so/saltstack/local/salt/elasticsearch/files/ingest/syslog
```

Add this block before the `common` pipeline processor, replacing `192.0.2.1`
and `192.0.2.2` with your own routers' actual IP addresses. The addresses shown
are RFC 5737 documentation placeholders — they must be changed:

```json
{
  "pipeline": {
    "name": "asus",
    "ignore_failure": true,
    "if": "ctx.log?.source?.address != null && (ctx.log.source.address == '192.0.2.1' || ctx.log.source.address == '192.0.2.2' || ctx.log.source.address.toString().startsWith('192.0.2.1:') || ctx.log.source.address.toString().startsWith('192.0.2.2:'))"
  }
}
```

### 3. Register the pipelines

The first time, restart Elasticsearch to let salt register all six files:

```bash
sudo so-elasticsearch-restart
```

**Note:** this restart can take several minutes on home-lab hardware. If it
hangs for more than 15 minutes, kill it, clear the salt lock, and retry:

```bash
sudo pkill -f so-elasticsearch-restart
sudo rm -f /var/cache/salt/minion/proc/*
sudo salt-call state.apply elasticsearch
```

### 4. Verify

In Kibana Dev Tools:

```
GET _ingest/pipeline/asus*
```

All six pipelines should be listed.

### 5. Test with a simulated document

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

Expected: `process.name: "hostapd"`, `event.dataset: "wireless"`,
`event.action: "wireless-associated"`, `source.mac: "AA-BB-CC-DD-EE-FF"`.

## Updating pipelines (no restart needed)

Once Elasticsearch is running, pipeline changes take effect immediately via
the REST API — no `so-elasticsearch-restart` required:

In Kibana Dev Tools:

```
PUT _ingest/pipeline/asus.wireless
{ ...updated file contents... }
```

Also update the file on disk so the next salt run doesn't overwrite your change:

```bash
sudo cp pipelines/asus.wireless \
    /opt/so/saltstack/local/salt/elasticsearch/files/ingest/asus.wireless
```

`so-elasticsearch-restart` is only needed for container-level changes (heap
size, TLS config, network bind address) — not for ingest pipeline updates.

## Searching in Hunt

```
event.module:"asus" | groupby event.dataset
```

All correctly parsed events have `event.module: "asus"` set as the very first
step regardless of dataset, making this the most reliable way to find all
router traffic without knowing the specific dataset values.

## Running the tests

Requires Python 3 only, no external dependencies.

Synthetic test suite (runs in CI and locally):

```bash
python3 tests/run_tests.py
```

With bulk validation against a real capture (not included in this repo):

```bash
python3 tests/run_tests.py /path/to/syslog.txt
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Design notes

See [DESIGN.md](DESIGN.md) for the root-cause analysis of the v1–v8
`process.name` bug, why the header grok is written the way it is, and why
`event.dataset` is explicitly removed at the start of the entry pipeline.
