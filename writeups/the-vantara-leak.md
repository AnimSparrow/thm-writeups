[![The Vantara Leak](https://github.com/AnimSparrow/thm-writeups/raw/main/assets/banners/the-vantara-leak.svg)](/AnimSparrow/thm-writeups/blob/main/assets/banners/the-vantara-leak.svg)

[![](https://img.shields.io/badge/TRYHACKME-1a0633?style=for-the-badge&labelColor=FF2A6D)](https://tryhackme.com/room/thevantaraleak)
[![](https://img.shields.io/badge/MEDIUM-1a0633?style=for-the-badge&labelColor=00F0FF)](#)
[![](https://img.shields.io/badge/DFIR-1a0633?style=for-the-badge&labelColor=A479C4)](#)
[![](https://img.shields.io/badge/BLUE_TEAM-1a0633?style=for-the-badge&labelColor=A479C4)](#)

- **Room:** [The Vantara Leak](https://tryhackme.com/room/thevantaraleak)
- **Category:** DFIR / Windows Endpoint Forensics
- **Difficulty:** Medium
- **Key skills:** KAPE triage, Prefetch / Amcache / MFT analysis, registry forensics (SAM, UserAssist), LNK & scheduled-task analysis, Windows event-log IR, attack-timeline reconstruction

---

## Overview

> [!NOTE]
> **TL;DR** — A finance workstation at Vantara Financial Group was compromised through a trojanised `VPNSetup` installer run from **Downloads**. The installer used `certutil` to drop a `svchost`-masquerading payload into `%TEMP%`, registered a scheduled task disguised as an Edge updater for persistence, ran host/domain reconnaissance, attempted lateral movement with a stolen **domain service account**, planted a **rogue local account**, and staged a financial document into a small archive under `\Windows\Temp` for exfil. Reconstructed end-to-end from a **KAPE** triage collection using the **Eric Zimmerman** toolset.

You are dropped in as a TSS (THM Security Services) analyst. No live box to pop — this is pure endpoint forensics. A KAPE artefact package and a forensic workstation are provided; the job is to rebuild the intrusion timeline and answer twelve investigative questions.

## Evidence & Tooling

Artefacts and tools shipped on the workstation:

```text
C:\Users\DFIRUser\Vantara-Artefacts.zip        # KAPE triage collection
C:\Users\DFIRUser\DFIR Tools\                   # EZ Tools, Registry Explorer, HxD, etc.
```

The three parsers that carry most of the case, run first so everything else can be cross-referenced against them:

```powershell
# Execution evidence — run counts + timestamps
PECmd.exe        -d ".\C\Windows\Prefetch" --csv C:\out

# Hashes + full paths for anything that executed
AmcacheParser.exe -f ".\C\Windows\AppCompat\Programs\Amcache.hve" --csv C:\out -i

# File system truth — sizes, paths, timestamps
MFTECmd.exe      -f ".\C\`$MFT" --csv C:\out
```

> [!TIP]
> Open the CSVs in **Timeline Explorer**, not Notepad++. Column filters on `ExecutableName`, `EventId`, and `Extension` turn a 400 MB `$MFT` dump into a two-click lookup. The whole case pivots on one timeline; build it once and every answer falls out of it.

The incident date drops out of the first Prefetch sort: **2026-06-05**, with all attacker activity between roughly **05:35 and 06:26**. Everything below lives in that window.

## Initial Access

Prefetch shows a single executable launched out of a user's Downloads folder on the incident date:

```text
2026-06-05 05:35:48  \USERS\DANIEL.AVERY\DOWNLOADS\VPN********.EXE
```

Interactive (GUI) execution is confirmed via **UserAssist**, and the path speaks for itself — a user double-clicked a "VPN setup" installer they had just downloaded. This is patient zero for the whole timeline.

The SHA1 comes straight from **Amcache** (`UnassociatedFileEntries` — the `AssociatedFileEntries` table was header-only):

```text
Name    : VPN********.exe
FullPath: c:\users\daniel.avery\downloads\vpn********.exe
SHA1    : d3c83599******************************d157
```

> [!TIP]
> Amcache splits records across `AssociatedFileEntries` and `UnassociatedFileEntries`. If one is empty, the other has your row — don't conclude "not found" from a single table.

**Q1** initial executable · **Q2** SHA1 — both recovered.

## Execution & Delivery

Minutes after the installer runs, a native Windows LOLBin fires — the classic download/decode primitive:

```text
2026-06-05 06:01:40  \WINDOWS\SYSTEM32\CERT****.EXE
2026-06-05 06:01:48  \USERS\DANIEL.AVERY\APPDATA\LOCAL\TEMP\SVC*****.EXE
```

Eight seconds separate the LOLBin from the appearance of the next-stage payload in `%TEMP%`. The payload's filename is a near-miss of a core Windows process — an extra character bolted onto `svchost` — the textbook **masquerading** trick to blend into a process list. Amcache confirms the *real* `svchost.exe` in `System32` is legitimate (different SHA1), so the `%TEMP%` copy is the impostor.

**Q3** delivery LOLBin · **Q4** impersonated process — done.

## Persistence

The malicious scheduled task hides in plain sight among the legitimate ones. Parsing `\Windows\System32\Tasks\`, one XML stands out — authored by the contractor account, created in the attack window, and pointing at the `%TEMP%` payload:

```xml
<RegistrationInfo>
  <Date>2026-06-05T06:01:15</Date>
  <Author>VFG-CTR-W019\daniel.avery</Author>
  <URI>\Microsoft**************Core</URI>
</RegistrationInfo>
...
<Actions Context="Author">
  <Exec>
    <Command>C:\Users\daniel.avery\AppData\Local\Temp\svc*****.exe</Command>
  </Exec>
</Actions>
```

The task name mimics a Microsoft Edge update service — legitimate-sounding chrome over a payload launcher. The sibling `Amazon Ec2 Launch` task in the same folder is genuine AWS tooling and a good reminder to verify, not assume.

**Q5** task name · **Q6** task command path — pulled from the XML.

## Discovery

Immediately after persistence, the attacker enumerates the host and the domain. Prefetch lays the recon burst out in order:

```text
2026-06-05 06:02:05  WHOAMI.EXE          # identity
2026-06-05 06:02:11  NET.EXE / NET1.EXE  # accounts / groups
2026-06-05 06:02:32  NL****.EXE          # domain trust enumeration
2026-06-05 06:05:06+ WMIC.EXE (xN)       # system / lateral prep
2026-06-05 06:19:43  QUSER / QUERY       # sessions
```

The trust-enumeration binary (`nltest /domain_trusts`) answers the recon-tool question directly.

For the user-discovery count, Prefetch's **RunCount** column is the single source of truth — it aggregates every execution of `whoami.exe` on the host (ten by the contractor's normal activity, one by the attacker via PowerShell):

```text
ExecutableName : WHOAMI.EXE
RunCount       : 1*
```

**Q7** trust-enum tool · **Q12** `whoami, 1*` — both confirmed against Prefetch.

## Lateral Movement

`Security.evtx`, filtered to **4648** (logon with explicit credentials) in the attack window, is where lateral movement shows up. The trap here is the prefix:

```text
Target: VFG-CTR-W019\Administrator   # LOCAL account — the hostname is the prefix
Target: VFG\svc.******               # DOMAIN account — short NetBIOS domain prefix
```

> [!WARNING]
> `HOSTNAME\account` (name with hyphens / host suffix) is a **local** account. `DOMAIN\account` (short NetBIOS name) is a **domain** account. The question asks for the domain account used in the lateral attempt — `VFG-CTR-W019\Administrator` is a decoy; the real answer carries the `VFG\` domain prefix and is a **service account**.

**Q8** domain account — identified from Event ID 4648.

## Credential Access — Rogue Account

Loading the **SAM** hive in Registry Explorer and walking `SAM\Domains\Account\Users\Names`, one account does not belong next to the built-ins:

```text
Administrator   2021-03-17   (legit)
daniel.avery    2026-06-05   (user)
DefaultAccount  2021-03-17   (legit)
Guest           2021-03-17   (legit)
help****$       2026-06-05 06:02:59   <-- created mid-attack
WDAGUtility...  2021-03-17   (legit)
```

The trailing `$` mimics a machine/service account to blend in, and the key's last-write timestamp lands squarely in the recon burst. Confirmed by a fresh high-RID key (`0x3F1`) under `...\Users\` with the same creation time.

**Q9** rogue local account — recovered from SAM.

## Collection & Staging

Two artefacts close the case. First, the financial document opened during the attack — recovered from LNK files in `...\Recent\` (the profile's `NTUSER.DAT` was not in the collection, so JumpList / LNK metadata carried it instead):

```powershell
LECmd.exe -d "...\daniel.avery\AppData\Roaming\Microsoft\Windows\Recent" --csv C:\out
```

Ten finance-themed LNKs exist, but only two have a `SourceCreated` of **2026-06-05 06:05:16** — inside the attack window. One points at a *folder*; the other at an actual document:

```text
Q1_2026_*******_Summary.lnk  ->  ...\FinanceReports\Q1_2026_*******_Summary.txt
SourceCreated: 2026-06-05 06:05:16
```

The rest were opened by the contractor back in May — legitimate work, not the attack. Timestamp discipline is what separates the real answer from the noise.

Second, the staging archive. Searching the parsed `$MFT` for archive extensions and filtering to system directories:

```text
ParentPath : .\Windows\Temp
FileName   : data_backup.zip
FileSize   : 4**            # bytes
Created    : 2026-06-05 06:04:29
```

A `data_backup.zip` in `\Windows\Temp`, created mid-attack — collection staged for exfil. (The `kape.zip` hit in the same search is the triage tool's own output; ignore it.)

**Q10** financial document · **Q11** archive size in bytes — both from LNK + MFT.

## Attack Timeline (ATT&CK-mapped)

| Time (2026-06-05) | Action | Technique |
| --- | --- | --- |
| 05:35:48 | Trojanised `VPNSetup` run from Downloads | T1204.002 User Execution |
| 06:01:15 | Scheduled task `Microsoft…Core` registered | T1053.005 Scheduled Task |
| 06:01:40 | `certutil` delivers next stage | T1105 Ingress Tool Transfer |
| 06:01:48 | `svchost`-masquerading payload in `%TEMP%` | T1036.005 Masquerading |
| 06:02:05–06:02:32 | `whoami` / `net` / `nltest` recon | T1033, T1087, T1482 |
| 06:02:59 | Rogue local account `help****$` created | T1136.001 Create Account |
| 06:04:29 | `data_backup.zip` staged in `\Windows\Temp` | T1074.001 Data Staged |
| 06:05:16 | Financial document opened | T1005 Data from Local System |
| 06:0x | Domain service account used for lateral attempt | T1021 / T1078 Valid Accounts |

## Findings

> [!NOTE]
> Values masked — **The Vantara Leak** is an active Premium room. The methodology above reconstructs every answer; the literal strings are left for you to earn.

| # | Question | Source artefact | Answer |
| --- | --- | --- | --- |
| 1 | Interactive exe from Downloads | Prefetch / UserAssist | `VPN********.exe` |
| 2 | SHA1 of that exe | Amcache | `d3c83599…d157` |
| 3 | Native binary that delivered stage 2 | Prefetch | `cert****.exe` |
| 4 | Process the payload impersonated | Amcache / MFT | `svc****.exe` |
| 5 | Persistence scheduled task name | Tasks XML | `Microsoft…Core` |
| 6 | Full task command path | Tasks XML | `…\Temp\svc*****.exe` |
| 7 | Domain trust enumeration tool | Prefetch / PS logs | `nl****` |
| 8 | Domain account in lateral movement | Security 4648 | `VFG\svc.******` |
| 9 | Rogue local account | SAM hive | `help****$` |
| 10 | Financial document opened | LNK / Recent | `Q1_2026_*******_Summary.txt` |
| 11 | Staging archive size (bytes) | MFT | `4**` |
| 12 | User-discovery command + count | Prefetch RunCount | `whoami, 1*` |

## Lessons learned

- **Build the timeline once.** Prefetch + Amcache + MFT parsed up front gives you an execution spine; nine of twelve answers are just lookups against it. Chasing questions individually is how you burn an hour.
- **Timestamps disambiguate, names don't.** Ten finance LNKs, one answer — the discriminator was a `SourceCreated` inside the attack window, not the filename. Same lesson on the scheduled task (one malicious among legit) and the rogue account (last-write time in the recon burst).
- **`HOSTNAME\` ≠ `DOMAIN\`.** The `VFG-CTR-W019\Administrator` decoy nearly ate the lateral-movement answer. A local account wearing the word "Administrator" is not a domain account. Read the prefix before you read the name.
- **Amcache tables split, profiles come partial.** Empty `AssociatedFileEntries` didn't mean "no hash" — the row was in `Unassociated`. A missing `NTUSER.DAT` didn't kill RecentDocs — LNK metadata covered it. Know the fallback for every primary artefact.

---

[![More writeups on GitHub](https://github.com/AnimSparrow/thm-writeups/raw/main/assets/more_writeups.svg)](https://github.com/AnimSparrow/thm-writeups)
