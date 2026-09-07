<p align="center">
  <img src="../assets/banners/trusted-by-default.svg" width="820" alt="Trusted By Default">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/TRYHACKME-1a0633?style=for-the-badge&labelColor=FF2A6D">
  <img src="https://img.shields.io/badge/MEDIUM-1a0633?style=for-the-badge&labelColor=00F0FF">
  <img src="https://img.shields.io/badge/SOC-1a0633?style=for-the-badge&labelColor=A479C4">
  <img src="https://img.shields.io/badge/BLUE_TEAM-1a0633?style=for-the-badge&labelColor=A479C4">
</p>

- **Room:** [Trusted By Default](https://tryhackme.com/room/trustedbydefault)
- **Category:** SOC / SIEM Investigation (Splunk)
- **Difficulty:** Medium
- **Key skills:** Splunk SPL, multi-source correlation (IIS · Zeek · Windows Security), rare-event hunting, Windows logon-type analysis, group-membership / privilege-abuse detection, RDP lateral-movement reconstruction, exfil-staging identification

---

## Overview

> [!NOTE]
> **TL;DR** - A service account (`svc-web***`) that Aurora Retail *trusts by default* is abused end-to-end from a single anomalous portal `POST`. The account is quietly added to a privileged file-server group by an insider-looking user, pivots over **RDP** to the file server, and an archive is staged on the destination host over **WebDAV** for exfil. The entire intrusion fits inside a **~45-second window on 2026-08-11**, reconstructed from Splunk telemetry alone (IIS · Zeek · Windows event logs).

You are dropped in as a TSS (THM Security Services) analyst. No box to pop - this is pure log-driven IR. A Splunk instance holds the estate's telemetry; the job is to rebuild the intrusion timeline and answer ten investigative questions. The trap is in the name: every action the account takes is individually *authorised*, so signature hunting finds nothing. The case is won by **correlation and rare-event hunting**, not by a single smoking-gun IOC.

## Evidence & Tooling

One Splunk index carries the whole case. Scope the data before hunting - don't guess field names:

```spl
index=* | stats count by sourcetype
index=* | stats count by host
```

That surfaces the sources and the hosts the timeline runs across:

```text
sourcetype                              host
------------------------------------    -----------------------------
iis                        (web POST)   AUR-WEB01(.aurora.local)   portal
zeek:conn / zeek:rdp       (network)    AUR-DC01.aurora.local      DC
zeek:http / dns / ssl                   AUR-FS01.aurora.local      file server
XmlWinEventLog:Security    (logons)     AUR-WEBDAV01               staging
aurora:webdav  (5 events - outlier!)
```

> [!TIP]
> Volume *is* the signal here. `method=POST` returns **one** event; `aurora:webdav` holds **five**. When a log type is that thin, the rare rows are the incident. Anchor everything to one timestamp - once you find the POST at `09:16:31`, every other artefact brackets around it.

## Initial Access

Only two `POST` requests exist in the entire dataset. That alone narrows it to one:

```spl
index=* sourcetype=iis method=POST | table _time, _raw
```

```text
2026-08-11 09:16:31  10.81.70.212  POST  /portal/s******.aspx  ticket=SR-*****
80  -  10.81.73.**  HTTP/1.1  Aurora-Remote-Support/1.6  ...  200
```

Reading the W3C fields: the request targets a portal `.aspx` endpoint, from a client IP on the `10.81.73.x` range, riding a bespoke user-agent `Aurora-Remote-Support/1.6` - not a browser. That client IP is patient zero and the source-side pivot for the rest of the case.

**Q1** POST URI path · **Q2** source IP - both recovered from the single IIS event.

## Execution

Correlate the request against Windows logons on the portal host. Batch logon = type **4**. The host is logged under two names (`AUR-WEB01` and `AUR-WEB01.aurora.local`), so wildcard it:

```spl
index=* sourcetype=XmlWinEventLog:Security host=AUR-WEB01* EventCode=4624 LogonType=4
| table _time, TargetUserName, LogonType, IpAddress
```

Among the daily scheduled batch logons, one lands at **`09:15:28`** - seconds before the POST - for the non-system account `svc-web***` (LogonType **4**). The "trusted by default" account doing exactly what it always does, at the exact moment the intrusion starts.

**Q3** batch-logon account · **Q4** logon type (`4`) - confirmed.

## Privilege Escalation

Look for account-manipulation events (`4728` global / `4732` local / `4756` universal) touching the portal service account:

```spl
index=* EventCode=4728 | table _time, _raw
```

At **`09:16:43`** on `AUR-DC01`, event **4728** - "member added to a security-enabled global group":

```text
MemberName     : CN=Portal Application Service,OU=Service Accounts,DC=aurora,DC=local
TargetUserName : FS-A*****      <-- the group that was modified
SubjectUserName: a.**           <-- who performed the change
```

The Portal Application Service account is added to a privileged file-server admins group by a named user. The group name telegraphs the objective - the file server is the next hop.

> [!WARNING]
> `4728` is a **global** group add; a local privileged group would log as **4732**. Check both. Here the group name itself is the lead - it tells you *where* the attacker is going before they get there.

**Q5** privileged group modified · **Q6** user who made the change - pulled from the 4728 EventData.

## Lateral Movement

With fresh privileges, confirm the account then logged into the file server. Hunt for a non-built-in account showing **both** network (3) and remote-interactive (10) logons:

```spl
index=* sourcetype=XmlWinEventLog:Security host=AUR-FS01* EventCode=4624
| stats values(LogonType) as types by TargetUserName
| search types=3 AND types=10
```

`svc-web***` returns LogonTypes **3, 10** (and 4). The remote-interactive logon - **LogonType 10** - is the RDP session. A service account should never interactively RDP anywhere; this is the sharpest behavioural break in the chain. Zeek's `rdp` log corroborates it with a single event:

```text
09:16:43  10.81.73.** -> 10.81.112.***:3389  cookie=svc-web***  encrypted  HYBRID
```

Same source IP as the POST, same account, same second as the group change.

**Q7** file-server account (network + remote-interactive) · **Q8** remote-interactive LogonType (`10`) - confirmed across Security 4624 + Zeek RDP.

### The sustained connection

Pivot on the POST source IP and pull all RDP in `zeek:conn`. Field names here have **no `id.` prefix** - read one raw record first, then match by IP + port:

```spl
index=* sourcetype=zeek:conn 10.81.73.** 3389 | table _time, _raw | sort _time
```

Most rows are throwaway probes to two hosts - `conn_state` `S0`/`RSTO`, **0 bytes**, sub-millisecond duration. One row at `09:16:43` is completely different:

```text
uid Cgx84o335HDknncsM5   10.81.73.** -> 10.81.112.***:3389   proto tcp   service ssl
duration 17.48s   orig_bytes 13018   resp_bytes 181***   conn_state RSTR
```

That is the **sustained** session - real duration, TLS-wrapped, real byte counts - versus the instantly-reset attempts around it. Its destination is the file server, and the bytes the destination returned answer the final question.

> [!TIP]
> `conn_state` encodes intent. `S0`/`RSTO` with 0 bytes = noise / probes; a genuine session has duration and bytes even when it ends in a reset (`RSTR`). Sort by **duration**, not by count, to separate the real pivot from the scan.

**Q9** destination IP of the sustained RDP · **Q10** `resp_bytes` returned - both from the one Zeek conn record with real volume.

## Collection & Staging

The WebDAV log (five events total) closes the loop:

```spl
index=* sourcetype=aurora:webdav | table _time, _raw
```

```text
09:17:12  10.81.112.***  MKCOL /drop/  201       <-- staging dir, seconds after the RDP landed
(earlier) 10.81.112.***  MKCOL /backup/ + PUT finance-backup-*.7z  201
```

A drop directory is created on the very host the attacker just RDP'd into, seconds after landing - the staging/exfil objective the briefing warned about.

## Attack Timeline (ATT&CK-mapped)

| Time (2026-08-11) | Action | Technique |
| --- | --- | --- |
| 09:15:28 | `svc-web***` batch logon (type 4) on AUR-WEB01 | T1078 Valid Accounts |
| 09:16:31 | Anomalous `POST` to portal `.aspx` (custom UA) | T1190 Public-Facing App |
| 09:16:43 | `a.**` adds Portal Service acct to `FS-A*****` | T1098 Account Manipulation |
| 09:16:43 | Sustained RDP `10.81.73.** -> 10.81.112.***` (17.5s) | T1021.001 Remote Services: RDP |
| 09:16:43+ | `svc-web***` network + remote-interactive logons on AUR-FS01 | T1078 Valid Accounts |
| 09:17:12 | `MKCOL /drop/` staging dir on file server | T1074.001 Data Staged |

## Findings

> [!NOTE]
> Values masked - **Trusted By Default** is an active room. The methodology above reconstructs every answer; the literal strings are left for you to earn.

| # | Question | Source artefact | Answer |
| --- | --- | --- | --- |
| 1 | Suspicious POST URI path | IIS | `/portal/s******.aspx` |
| 2 | Source IP of the POST | IIS | `10.81.73.**` |
| 3 | Batch-logon account on AUR-WEB01 | Security 4624 | `svc-web***` |
| 4 | Logon type (batch) | Security 4624 | `4` |
| 5 | Privileged group modified | Security 4728 | `FS-A*****` |
| 6 | User who performed the change | Security 4728 | `a.**` |
| 7 | FS account (network + remote-interactive) | Security 4624 | `svc-web***` |
| 8 | Remote-interactive LogonType number | Security 4624 | `10` |
| 9 | Destination IP of the sustained RDP | Zeek conn / rdp | `10.81.112.***` |
| 10 | `resp_bytes` of that connection | Zeek conn | `181***` |

## Lessons learned

- **Rare-event hunting beats signature hunting for "trusted" abuse.** Every action here was individually authorised. The anomalies were *volume* (one POST, five WebDAV events) and *behaviour* (a service account performing an interactive RDP), not any single malicious IOC.
- **Correlation is the whole game.** No single log solved it - IIS gave the entry, Windows Security gave the privilege change and the logon types, Zeek gave the sustained pivot and the byte counts. Anchor everything to one timestamp (`09:16:43`) and the story assembles itself.
- **Know your field names before you filter.** Empty results were almost always wrong field names (`LogonType` vs `Logon_Type`, Zeek `resp_h` vs `id.resp_h`) or a host logged under two names. Read one `_raw` per sourcetype first, then build the query.
- **`conn_state` disambiguates intent.** `S0`/`RSTO` at 0 bytes is scan noise; a real session carries duration and bytes even when it resets. Sort by duration, not count, and the sustained pivot separates cleanly from the probes.

---

[![More writeups on GitHub](https://github.com/AnimSparrow/thm-writeups/raw/main/assets/more_writeups.svg)](https://github.com/AnimSparrow/thm-writeups)
