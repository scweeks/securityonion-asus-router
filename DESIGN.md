# Design Notes

## The v1–v8 `process.name` bug

Versions 1 through 8 of this parser intermittently set `process.name` to a
wireless interface name (`wl1.2`, `wl3.1`, etc.) instead of the actual daemon
name (`hostapd`, `wlceventd`). The bug was chased through nine iterations
without being fully understood, because each version patched a new symptom
without addressing the root mechanism. This section documents what was actually
happening.

### How Security Onion's syslog pipeline works

SO's `ingest/syslog` pipeline runs first on every syslog event. For most
traffic it successfully parses the BSD syslog header — timestamp, hostname,
program name — using grok patterns that require a literal `<PRI>` prefix. If
`<PRI>` is present, `process.name` (via the `source.application` field) and
`real_message` (the post-header body) are populated. The pipeline then
dispatches to vendor pipelines for recognized sources.

### Why the upstream parse is unreliable for ASUS traffic

ASUS routers do not consistently include the `<PRI>` prefix. In traffic
captures, most lines have no prefix at all. Without `<PRI>`, the upstream
grok's primary pattern does not fire, so `source.application` is never set
and `real_message` contains the entire raw line including the syslog header.

Additionally, the upstream pattern uses `%{WORD}` for the program name field.
`%{WORD}` matches only `\w+` (alphanumerics and underscore), which cannot
match hyphenated daemon names like `dnsmasq-dhcp` or `avahi-daemon`.

### How v1–v8 introduced the bug

Rather than parsing the header itself, v1–v8 attempted to re-derive
`process.name` from whatever text the upstream pipeline left in `real_message`
or `_tmp.msg`. The fallback grok pattern used was:

```
^%{PROG:process.name}(?:\[pid\])?:\s*%{GREEDYDATA:_tmp.body}
```

`%{PROG}` matches `[\x21-\x5a\x5c\x5e-\x7e]+` — any non-whitespace,
non-bracket run of characters, **including colons**. When `hostapd` logged:

```
Jun 10 12:06:18 hostapd: wl1.2: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated
```

and the upstream pipeline had already stripped the header, `real_message`
contained:

```
wl1.2: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated
```

The fallback grok's unanchored `%{PROG}` matched `wl1.2` as the program name,
producing `process.name: "wl1.2"`. Every subsequent dispatch condition keyed
on `process.name == 'hostapd'` was then false, so hostapd events fell through
to the catch-all with an incorrect process name.

`wlceventd` happened to work in v8 because its body text always contains the
literal string `wlceventd_proc_event`, so a content-based bypass check rescued
it. That bypass was the fix for the symptom, not the cause.

## The v9 fix: parse from `message`, not `real_message`

The entry pipeline now parses the BSD header directly from the original
`message` field in a single grok pass, independent of what the upstream
pipeline did or did not manage to extract:

```
^(?:<%{POSINT:syslog.priority:int}>)?
 %{SYSLOGTIMESTAMP:syslog.timestamp}\s+
 (?:%{ASUSHOST:syslog.host}\s+)?
 %{PROG:process.name}(?:\[%{POSINT:process.pid:int}\])?:\s*
 %{GREEDYDATA:_tmp.body}
```

### Why ASUSHOST excludes colons

The hostname slot uses a custom pattern `ASUSHOST = [^\s:]+` rather than
grok's built-in `NOTSPACE = \S+`. The critical difference: `ASUSHOST` excludes
the colon character.

Without this exclusion, if the hostname slot is optional and a line has no
hostname, `NOTSPACE` can greedily absorb a colon-terminated program tag into
the hostname slot. For example, in `hostapd: wl1.2: STA ...`, `NOTSPACE` could
match `hostapd:` as the hostname, leaving `wl1.2` as the next token, which
then matches `%{PROG:process.name}` — reproducing the same bug through a
different path.

`ASUSHOST` stops at the colon, which means:
- A hostname like `RT-BE98_Pro` matches normally (no colon)
- A program tag like `hostapd:` stops the hostname match at the colon, forcing
  the grok engine to backtrack and try the pattern without a hostname — which
  then correctly identifies `hostapd` as the program name

This was validated empirically against real Asus log shapes including the
underscore-hostname edge case.

## Why `event.dataset` is removed at the top of the entry pipeline

The platform's `ingest/syslog` pipeline sets `event.dataset = "syslog"` as a
default before calling vendor pipelines. This is intentional for events that
have no vendor pipeline — they correctly end up as `system.syslog`.

For events that do have a vendor pipeline, the vendor is supposed to replace
this default with the correct value. Our five dispatch conditions all gate on
`ctx.event?.dataset == null`. If this removal step were absent, those guards
would find `event.dataset = "syslog"` (non-null) and skip dispatch entirely,
leaving every event as `asus.syslog`.

The removal step is a deliberate, required part of the pipeline contract — not
cleanup or a workaround. The `common` pipeline's auto-concatenation of
`event.module` + `event.dataset` is what produces the final `asus.firewall`,
`asus.wireless`, etc. values, and it can only do so correctly if we set
`event.dataset` to the bare suffix (`firewall`, `wireless`) after the entry
pipeline's default has been cleared.

## Why the `@timestamp` date processor is not redundant

The platform's `ingest/syslog` pipeline runs a date processor assuming UTC.
ASUS routers log in local time with no timezone in the BSD timestamp. The date
processor in `asus` re-runs the conversion with `timezone: America/New_York`
to overwrite the incorrect assumption. This is required for a correct
`@timestamp`, not a duplicate.

If your routers are in a different timezone, update this value in the `asus`
entry pipeline.

## Why kernel wireless errors route to `asus.wireless`

SBF, WLC_SCB_*, CFG80211-ERROR, and similar messages carry `process.name:
kernel` because the Broadcom wireless driver (`dhd`/`wl`) runs in kernel space
rather than as a userspace daemon. The log tag reflects where in the OS the
code lives, not the nature of the event. These messages reference specific
client MACs, beamforming parameters, and wireless layer error codes — they are
wireless events and belong in the `asus.wireless` dataset alongside hostapd
and wlceventd for correlation by `source.mac`.

Routing them to `asus.system` would scatter related events across two datasets
and break per-client session correlation.

## Why the `community_id` processor requires no special handling

Elasticsearch's built-in `community_id` processor is called directly in
`asus.firewall`. It uses the already-populated `source.ip`, `source.port`,
`destination.ip`, `destination.port`, and `network.transport` fields and
writes to the default target `network.community_id`. The Python test harness
does not simulate community_id (it requires native libraries), but the field
is correctly populated in production.
