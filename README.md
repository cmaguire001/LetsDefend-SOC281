# SOC281 — System Network Configuration Discovery Detected

**Platform:** LetsDefend
**EventID:** 258
**Event Time:** 2024-05-14T08:42:00+03:00
**Rule:** SOC281 — System Network Configuration Discovery Detected
**Alert Type:** Malware
**Difficulty:** Medium
**Role:** Incident Responder
**MITRE ATT&CK:** T1016, T1566.002, T1047, T1059.001, T1059.003, T1204.002, T1098, T1197, T1087
**Host:** Andrew
**Source Address:** 172.16.17.97

## 1. Alert Summary

A Windows host named **Andrew** triggered a detection for network configuration discovery. The alert fired when a process invoked:

    C:\Windows\system32\cmd.exe /c ipconfig /all

The parent process was:

    C:\Users\LetsDefend\Downloads\20\20.exe

The L1 analyst noted that a file was shared via a URL in an email from **jame@cleanpatron.top**, but could not confirm whether the application was actually downloaded and executed.

## 2. Initial Triage

The detection maps to **MITRE T1016 — System Network Configuration Discovery**, a technique adversaries use after initial access to map the victim's network before lateral movement or C2 communication.

| Indicator | Value | Why it matters |
|---|---|---|
| Parent process | `C:\Users\LetsDefend\Downloads\20\20.exe` | Executable in a Downloads subfolder — typical malware staging location |
| Child process | `cmd.exe /c ipconfig /all` | Living-off-the-land binary used for recon |
| Current directory | `C:\Users\LetsDefend\Downloads\cleaner\` | Consistent with an extracted archive or dropped payload |
| Sender domain | `cleanpatron.top` | `.top` TLD frequently abused for phishing/malware delivery |
| L1 note | File shared via email URL | Suggests phishing as the initial vector |

Core question L1 could not answer: **did the malware actually execute?**

## 3. Investigation

### 3.1 Process lineage

The parent-child relationship is the decisive evidence. `20.exe` spawned `cmd.exe`, which ran `ipconfig /all`. That means `20.exe` **did execute** — it is not sitting dormant in the Downloads folder. The `ipconfig` call is proof of execution.

### 3.2 Technique analysis

`ipconfig /all` is a standard Windows diagnostic command, but in this context it is malicious. A legitimate user rarely runs `ipconfig /all` by double-clicking an unknown executable in their Downloads folder. The behavior pattern — unknown binary → shell → network discovery — is a well-documented malware precursor.

### 3.3 Initial access vector

The email from `jame@cleanpatron.top` is the likely delivery mechanism (T1566.002 — Spearphishing Link). The `.top` TLD and the brand-lookalike domain ("cleanpatron") are consistent with commodity malware campaigns.

### 3.4 Missing telemetry

L1 could not confirm whether the payload was downloaded via the email link. This is a gap to close by checking:

- Browser history on host **Andrew** for the URL in the email
- Email gateway logs for the `cleanpatron.top` domain
- File system timeline for when `20.exe` landed in `C:\Users\LetsDefend\Downloads\20\`

## 4. Verdict

**True Positive — Malware Execution with Reconnaissance Activity**

Reasoning:

1. The parent process `20.exe` executed from a Downloads subfolder — no legitimate business justification.
2. It spawned `cmd.exe` to run `ipconfig /all` — behavior consistent with T1016.
3. The delivery vector (phishing email from `cleanpatron.top`) matches known malware distribution patterns.
4. The presence of the `ipconfig` command **proves execution** — this is not a dormant file.

**Recommended escalation:** Tier 2 / Incident Response. Isolate host **Andrew**, capture memory and disk artifacts, block the sender domain and any resolved C2 IPs at the perimeter, and reset any credentials used on that host.

## 5. Lessons Learned

- **L1 note quality matters.** The original note said "could not understand whether the application was downloaded." The process lineage alone answers that — always check parent-child relationships before escalating with open questions.
- **`ipconfig` is not benign in context.** Alone it's a diagnostic. Spawned by an unknown binary from a Downloads folder, it's an attack indicator.
- **Domain reputation is a fast signal.** `.top` TLD + brand-lookalike name = high suspicion before any further analysis.
