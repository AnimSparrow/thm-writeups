<!--
  Writeup — AnimSparrow synthwave-terminal identity.
  Banner: generate assets/banner.png from the ChatGPT prompt, commit it, keep this <img> path.
  Difficulty pill: confirm the real value on the room page and adjust the shields badge below.
-->

<p align="center">
  <img src="assets/banner.png" width="820" alt="Trusted By Default">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/TRYHACKME-1a0633?style=for-the-badge&labelColor=FF2A6D">
  <img src="https://img.shields.io/badge/MEDIUM-1a0633?style=for-the-badge&labelColor=00F0FF">
  <img src="https://img.shields.io/badge/SOC_%C2%B7_DFIR_%C2%B7_SPLUNK-1a0633?style=for-the-badge&labelColor=A479C4">
</p>

<p align="center">
  <b>Room:</b> <a href="https://tryhackme.com/room/trustedbydefault">Trusted By Default</a> ·
  <b>Client:</b> Aurora Retail Group · <b>Discipline:</b> Blue Team / Incident Response
</p>

---

## Overview

> [!NOTE]
> **TL;DR** — A trusted service account (`svc-webapp`) is abused through an exposed
> portal endpoint. A single anomalous `POST` kicks off the chain: the account is
> quietly slipped into a privileged file-server group, pivots over RDP, and stages
> an archive for exfiltration over WebDAV. The whole incident fits inside a ~45-second
> window on **2026-08-11**. The job is to reconstruct it from Splunk alone.

The environment is a Splunk instance holding IIS, Zeek (`conn`/`http`/`rdp`/`dns`/`ssl`),
and Windows (`XmlWinEventLog:Security` + Sysmon) telemetry across the Aurora estate:

| Host | Role |
|---|---|
| `AUR-WEB01(.aurora.local)` | Public customer portal |
| `AUR-DC01.aurora.local` | Domain controller |
| `AUR-FS01.aurora.local` | File server |
| `AUR-WEBDAV01` | WebDAV endpoint (staging) |

The trap in the name: the service account is *trusted by default*. Nothing screams
"malware" — every step looks like something the account is allowed to do. The
investigation is about **correlation across sources**, not a single smoking-gun IOC.

## Method — scope the data first

Before hunting, map what you actually have. Don't guess field names.

```spl
index=* | stats count by sourcetype
index=* | stats count by host
```

That surfaces `aurora:webdav` (only **5** events — instant outlier), the IIS logs, the
Zeek network logs, and confirms the Windows logon field is `LogonType` (no underscore).

## Phase 1 — Initial access · the anomalous POST

Only two events in the whole dataset are `POST` requests. That alone is the signal.

```spl
index=* sourcetype=iis method=POST | table _time, _raw
```

One hit, at `09:16:31`:

```
2026-08-11 09:16:31  10.81.70.212  POST  /portal/status.aspx  ticket=SR-48228
80  -  10.81.73.36  HTTP/1.1  Aurora-Remote-Support/1.6  -  -  ...  200 ...
```

Reading the W3C fields: the request hits **`/portal/status.aspx`**, comes from client
IP **`10.81.73.36`**, and rides a bespoke user-agent `Aurora-Remote-Support/1.6` — not
a normal browser. That client IP is our source-side pivot for the rest of the case.

> [!TIP]
> When a log type has almost no volume (`method=POST` → 1 event, `aurora:webdav` → 5),
> that *is* the finding. Rare-event hunting beats signature hunting for insider-style
> abuse where every action is individually "authorised".

## Phase 2 — Execution · batch logon on the web server

Correlate the request against Windows logons on the portal host. Batch logon = type 4.
Note the host appears both as `AUR-WEB01` and `AUR-WEB01.aurora.local`, so wildcard it.

```spl
index=* sourcetype=XmlWinEventLog:Security host=AUR-WEB01* EventCode=4624 LogonType=4
| table _time, TargetUserName, LogonType, IpAddress
```

Among the daily scheduled batch logons, one lands at **`09:15:28`** — seconds before the
POST — for the non-system account **`svc-webapp`** (Logon Type **4**). This is the
"trusted by default" account doing what it always does… right as the intrusion starts.

## Phase 3 — Credential access / privilege · quiet group change

Next, look for account-manipulation events (`4728`/`4732`/`4756`) touching the portal
service account.

```spl
index=* EventCode=4728 | table _time, _raw
```

At **`09:16:43`** on `AUR-DC01`, event **4728** ("member added to a security-enabled
global group"):

```
MemberName     : CN=Portal Application Service,OU=Service Accounts,DC=aurora,DC=local
TargetUserName : FS-Admins        ← the group that was modified
SubjectUserName: a.ng             ← who performed the change
```

The Portal Application Service account is added to the privileged **`FS-Admins`** group
by user **`a.ng`**. That group name is the giveaway for *where* the attacker is heading
next — the file server.

> [!WARNING]
> `4728` is a **global** group add; a local privileged group would log as `4732`. Check
> both. Here the group name (`FS-Admins`) telegraphs the objective, which is why the
> next pivot is the file server, not the DC.

## Phase 4 — Lateral movement · RDP to the file server

With fresh privileges, confirm the account then logged into `AUR-FS01`. Look for a
non-built-in account showing **both** network (3) and remote-interactive (10) logons.

```spl
index=* sourcetype=XmlWinEventLog:Security host=AUR-FS01* EventCode=4624
| stats values(LogonType) as types by TargetUserName
| search types=3 AND types=10
```

`svc-webapp` comes back with LogonTypes **3, 10** (and 4). The remote-interactive
logon — **LogonType 10** — is the RDP session. A service account should never
interactively RDP anywhere; this is the clearest behavioural break in the chain.

Confirm it on the wire. Zeek's `rdp` log has a single event:

```spl
index=* sourcetype=zeek:rdp | table _time, _raw
```

```
09:16:43  10.81.73.36 → 10.81.112.251:3389  cookie=svc-webapp  encrypted  HYBRID
```

Same source IP as the POST, same account, same second as the group change.

## Phase 5 — The sustained connection · pivot on the source IP

Use the POST source IP as the source-side pivot and pull all RDP in `zeek:conn`. Field
names here have **no `id.` prefix** — read a raw record first, then match by IP + port.

```spl
index=* sourcetype=zeek:conn 10.81.73.36 3389
| table _time, _raw | sort _time
```

Most rows are throwaway probes to two hosts — `conn_state` `S0`/`RSTO`, **0 bytes**,
sub-millisecond duration. One row is completely different, at `09:16:43`:

```
uid Cgx84o335HDknncsM5  10.81.73.36 → 10.81.112.251:3389  proto tcp  service ssl
duration 17.48s   orig_bytes 13018   resp_bytes 181717   conn_state RSTR
```

That is the **sustained** session — real duration, real byte counts, TLS-wrapped —
versus the instantly-reset attempts around it. Destination **`10.81.112.251`**, and the
data returned by the destination is **`resp_bytes = 181717`**.

## Phase 6 — Staging & exfil (the "why")

The WebDAV log closes the loop:

```spl
index=* sourcetype=aurora:webdav | table _time, _raw
```

```
09:17:12  10.81.112.251  MKCOL /drop/  201        ← staging dir created, right after the RDP
07-17     10.81.112.251  MKCOL /backup/ + PUT finance-backup-WeeklyOps-*.7z  201
```

An archive drop point is created on the same host the attacker just RDP'd into,
seconds after landing — the staging/exfiltration objective the briefing warned about.

## Timeline (2026-08-11)

| Time | Event | Source |
|---|---|---|
| `09:15:28` | `svc-webapp` batch logon (type 4) on AUR-WEB01 | Security 4624 |
| `09:16:31` | `POST /portal/status.aspx` from `10.81.73.36` (UA `Aurora-Remote-Support/1.6`) | IIS |
| `09:16:43` | `a.ng` adds Portal Application Service → `FS-Admins` | Security 4728 |
| `09:16:43` | RDP `10.81.73.36 → 10.81.112.251` — 17.5s, 181,717 resp bytes | Zeek conn/rdp |
| `09:16:43+` | `svc-webapp` network + remote-interactive logons on AUR-FS01 | Security 4624 |
| `09:17:12` | `MKCOL /drop/` staging dir on `10.81.112.251` | WebDAV |

## ATT&CK mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1078 Valid Accounts / T1190 Public-Facing App | POST to `/portal/status.aspx` |
| Privilege Escalation | T1098 Account Manipulation | 4728 add to `FS-Admins` |
| Lateral Movement | T1021.001 Remote Services: RDP | LogonType 10, Zeek RDP session |
| Collection / Staging | T1074 Data Staged | WebDAV `MKCOL /drop/`, `.7z` archive |

## Answer key

<details>
<summary>Spoiler — Task 2 answers (try it yourself first)</summary>

| # | Question | Answer |
|---|---|---|
| 1 | Suspicious POST URI path | `/portal/status.aspx` |
| 2 | Source IP of the POST | `10.81.73.36` |
| 3 | Batch-logon account on AUR-WEB01 | `svc-webapp` |
| 4 | Logon type (batch) | `4` |
| 5 | Privileged group modified | `FS-Admins` |
| 6 | User who made the change | `a.ng` |
| 7 | FS account w/ network + remote-interactive | `svc-webapp` |
| 8 | Remote-interactive LogonType number | `10` |
| 9 | Destination IP of the sustained RDP | `10.81.112.251` |
| 10 | `resp_bytes` of that connection | `181717` |

</details>

## Lessons learned

- **Rare-event hunting > signature hunting for "trusted" abuse.** Every action here was
  individually authorised. The anomalies were volume (one POST, five WebDAV events) and
  *behaviour* (a service account doing an interactive RDP), not any single malicious IOC.
- **Correlation is the whole game.** No single log solved it — IIS gave the entry, Windows
  Security gave the privilege change and the logon types, Zeek gave the sustained pivot and
  the byte counts. Anchor everything to one timestamp (`09:16:43`) and the story assembles.
- **Know your field names before you filter.** Empty results were almost always wrong field
  names (`LogonType` vs `Logon_Type`, Zeek `resp_h` vs `id.resp_h`) or a host logged under
  two names. Read one `_raw` record per sourcetype first, then build the query.
- **`conn_state` distinguishes intent.** `S0`/`RSTO` with 0 bytes = noise/probes; a real
  session has duration and bytes even if it ends in a reset (`RSTR`). Sort by duration, not
  by count.

---

<p align="center">
  <a href="https://tryhackme.com/room/trustedbydefault">
    <img src="https://img.shields.io/badge/MORE_WRITEUPS_%E2%86%92-1a0633?style=for-the-badge&labelColor=00F0FF">
  </a>
</p>
