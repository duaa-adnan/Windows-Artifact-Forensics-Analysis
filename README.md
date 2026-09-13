# Windows Artifact Analysis

## Overview
This was Week 8 of my Cyberster Blue Team internship, and it's the second part of the digital forensics phase that started in Week 7 with disk imaging. Instead of working from a full disk image this time, I looked at three artifact types that exist on every live Windows machine, the Security event log, Prefetch execution records, and the thumbcache, browser cache, and Recycle Bin data that together show what was viewed and what was deleted. I did all of this on my own personal Windows 11 laptop rather than a provided evidence file, which meant I had to be careful about redacting personal content before including anything in this report. The whole point of the week was learning to filter out the noise so the events that actually matter become visible, since a real investigator almost never gets a clean, pre labeled dataset.

## Objectives
- Build a baseline of my own normal, physical logon activity so future logons can be compared against something known instead of judged blindly
- Look at both successful and failed authentication events and actually understand what a failure code means instead of assuming any failure is suspicious
- Investigate how administrative privilege gets assigned on my machine (Event ID 4672) and tie it back to a real, explainable cause
- Tell apart human driven logons from the authentication Windows generates on its own for background services
- Parse the Prefetch directory, find the twenty most executed programs, and check each one against what's expected on a normal system
- Search all of Prefetch for programs run from unusual locations, since that's one of the most reliable signs of something malicious
- Build a seven day execution timeline and compare it against the event log baseline
- Parse the thumbcache database files and pull a sample of thumbnails while handling personal images responsibly
- Identify every browser on the machine and document what got cached and when
- Go through every entry in the Recycle Bin and recover the original path, deletion time, and whether the file content is still there
- Tie findings across all three artifact types together so conclusions rest on more than one source agreeing with each other

## Lab Architecture
This wasn't a multi machine lab like some of my other projects, it was my own personal Windows 11 laptop treated as the evidence source. I worked from an elevated PowerShell session the whole time since reading the live Security.evtx file, the Prefetch directory, the thumbcache databases, and the Recycle Bin all need administrator rights. Every artifact type got copied into its own dedicated working folder under C:\Forensics before I touched it, the same evidence handling discipline from the Week 7 disk imaging work, just applied to a live endpoint instead of a static image.

## Technologies Used
- EvtxECmd (Eric Zimmerman's EZ Tools) to parse the binary Security.evtx log into CSV
- PECmd (also EZ Tools) to parse .pf Prefetch files, including an auto generated timeline CSV
- Thumbcache Viewer to parse and export thumbnails from the thumbcache database
- ChromeCacheView to parse Chrome's cache, and also pointed at Edge's cache folder since NirSoft's dedicated Edge tool wasn't reachable
- A short custom PowerShell script using ReadAllBytes and BitConverter to manually parse the Recycle Bin's binary $I metadata files
- PowerShell (Import-Csv, Where-Object) for all actual filtering and analysis, instead of Excel

## Environment
Everything was done on my own Windows 11 laptop, all analysis run against copies rather than the live artifacts, with a SHA-256 hash generated for the Security.evtx copy and file counts recorded for the others (460 prefetch files, thirteen thumbcache databases, nineteen Recycle Bin entries) as a fixed reference point before any filtering started.

## Implementation
1. **Copied and hashed the Security log.** Made a working copy of Security.evtx and generated its SHA-256 hash before touching anything, then parsed it with EvtxECmd into a structured CSV. It processed 24,699 records cleanly with zero errors.
2. **Built a human authentication baseline (Day 53).** Filtered 4624 logon events down by Logon Type. Type 7 (unlock) events were all tied exclusively to my own account, six of them across a roughly nineteen and a half hour window, each backed up by a Type 2 UMFD/DWM cluster marking the same session start.
3. **Looked at the one failed logon (4625).** Only one 4625 existed in my window. I looked up its status/sub-status code instead of assuming it meant a mistyped password, and it turned out to be a known benign lock screen artifact, corroborated by a real unlock five seconds later.
4. **Investigated privilege assignment (Day 54, Event ID 4672).** Found 415 instances, cross referenced three of them against process creation activity, and traced them to the OS boot sequence, my own account's routine unlock time privilege grant, and the Wazuh SIEM agent doing a scheduled audit check. I couldn't find a clean example of a literal UAC click in my evidence window and said so directly instead of forcing a fit.
5. **Catalogued background service noise (Day 55).** Found exactly three built in accounts (SYSTEM, LOCAL SERVICE, NETWORK SERVICE) generating Logon Type 5 service authentication in volume, each explained by its normal Windows role.
6. **Parsed Prefetch (Days 56 to 57).** Copied 460 .pf files, parsed 459 successfully with PECmd (one failed with an invalid signature), and recovered source paths from the FilesLoaded field since PECmd doesn't give you a direct path column.
7. **Found the top 20 most executed programs and checked their source paths.** All twenty resolved to legitimate Program Files, System32, WindowsApps, or OneDrive locations.
8. **Searched for execution from suspicious locations.** Every genuinely flagged entry across the full 459 record dataset traced back to one of three explainable events, my own FTK Imager use from Week 7, one unrelated install/uninstall pair, and an Opera browser installation.
9. **Built a seven day execution timeline.** Out of 1,703 total execution events, only 14 were flagged, and all 14 mapped onto those same three events already explained.
10. **Correlated Prefetch against the event log baseline.** Found LockApp.exe and RuntimeBroker.exe firing seconds before the 13:01 failed logon and unlock cluster, independently confirming it was a normal lock/unlock transition.
11. **Parsed thumbcache (Days 58 to 59).** Located thirteen thumbcache database files, copied them (working around a file locking issue with robocopy), and used Thumbcache Viewer to pull 141 cached entries from thumbcache_256.db. Reviewed content carefully before choosing three thumbnails to include in the report.
12. **Checked browser cache.** Used ChromeCacheView on Chrome's cache and confirmed it was dominated by ordinary infrastructure traffic, then pointed the same tool at Edge's cache folder since Edge and Chrome share the same underlying format. Chrome showed active, minute by minute entries; Edge showed only background account sync traffic.
13. **Parsed the Recycle Bin.** Found nineteen $I metadata files under my account's SID folder, wrote a script to parse their binary layout (header, file size, FILETIME timestamp, path length, UTF-16 path), and confirmed thirteen still had recoverable $R content while six didn't.
14. **Correlated everything across all four artifact types.** Traced the same Opera installation event through Prefetch, the Recycle Bin, and the recoverable installer file itself, and traced the same 13:01 lock screen event through both the event log and Prefetch.

## Detection Workflow
```
Live Windows artifact (Security.evtx, Prefetch, thumbcache, browser cache, Recycle Bin)
        │
        ▼
Copied into a dedicated working folder before any parsing
        │
        ▼
Hashed or file-counted to establish a fixed reference point
        │
        ▼
Parsed into structured output using the matching tool
   (EvtxECmd / PECmd / Thumbcache Viewer / ChromeCacheView / custom script)
        │
        ▼
Schema confirmed on sample records before filtering at scale
        │
        ▼
All filtering and analysis done in PowerShell (Import-Csv, Where-Object)
        │
        ▼
Findings correlated against other artifact types already investigated
        │
        ▼
Conclusion only drawn once multiple independent sources agree
```

## Investigation Process
- Checked the raw parsed CSVs directly rather than trusting a spreadsheet view, after Excel Online silently corrupted my first export
- Looked up unfamiliar status/sub-status codes instead of guessing what a failure meant
- Cross referenced 4672 privilege events against 4688 process creation activity to find an actual explainable cause instead of accepting the event at face value
- Recovered execution paths from Prefetch's FilesLoaded field since there's no direct path column
- Caught and corrected a false positive where AppData\Local\Programs got flagged as suspicious when it's actually a normal per user install location
- Caught a silent gap where an executable name with parentheses broke my regex based path matching, and manually recovered those entries from the timeline data instead of letting the tool limitation hide them
- Reviewed thumbcache and browser cache content personally before deciding what could responsibly go into this report
- Verified Recycle Bin file counts two separate ways (parsed table vs raw file count) to make sure they matched

## Challenges & Troubleshooting
| Issue | What caused it | How I fixed it |
|---|---|---|
| Excel Online silently corrupted my first Security log CSV export | Excel's auto column detection misread the TimeCreated column and OneDrive's autosave overwrote the original file with the corrupted version | Regenerated a fresh CSV from the hash verified EVTX, renamed it to avoid touching the corrupted one, and moved all filtering into PowerShell for the rest of the week |
| EvtxECmd flagged "time just went backwards" while parsing | At least one point in the log where events aren't in strict chronological order, cause not fully identified | Documented it as an open observation rather than pretending it was resolved |
| One prefetch file failed to parse | MS-TEAMSUPDATE.EXE-DA0ECB6F.pf had an invalid internal signature | Noted it as a parsing limitation, not a finding |
| FTK Imager's Temp path execution got silently dropped from my suspicious locations filter | Its executable name has parentheses, which broke my regex based path matching | Manually recovered the entries from the seven day timeline data instead of letting it stay hidden |
| AppData\Local\Programs got flagged as suspicious | It sits under AppData, which my filter treated as inherently unusual | Reviewed it and excluded it, since it's actually a standard per user install location for apps like Opera and VS Code |
| Robocopy stalled while copying thumbcache_256.db | Explorer had an active file handle open on the database it was currently writing to | Let the copy keep retrying in the background and it succeeded on its own without needing to close Explorer |
| NirSoft's dedicated EdgeCacheView tool wasn't downloadable | Its usual download page wasn't reachable during my investigation | Pointed ChromeCacheView at Edge's Chromium based cache folder instead, since both browsers share the same cache format |
| My own elevated PowerShell session for this exercise wasn't captured in the log | The copied Security.evtx snapshot ended before I opened today's session | Stated this limitation directly instead of pretending the evidence window covered everything |

## Indicators of Compromise (IOCs)
This investigation was a baseline exercise on a known, trusted machine rather than an incident response case, so nothing here is a confirmed malicious indicator. Instead, these are the kinds of entries I specifically checked for and explained:
- The single 4625 failed logon (status 0xC000006D / sub-status 0xC0000380), explained as a benign lock screen artifact rather than a credential guessing attempt
- Programs executed from Temp, Downloads, or non-standard AppData paths (all nine flagged entries traced back to three explainable, legitimate events)
- Files deleted and stored in the Recycle Bin with recoverable content, useful for showing what evidence can survive even after a user thinks something is gone
- Thumbcache entries that reveal document content or type even when the original file no longer exists

## MITRE ATT&CK Mapping
This project was a forensic baseline exercise rather than an attack simulation, so there isn't really a mapping of adversary techniques to include. If anything, the artifacts examined here (event logs, Prefetch, thumbcache, browser cache, Recycle Bin) are the same data sources an analyst would use to detect techniques like T1078 (Valid Accounts), T1204 (User Execution), and T1070 (Indicator Removal) in a real investigation, but no such activity was actually present in this dataset.

## Results
- Built a clean baseline of six Type 7 unlock events tied exclusively to my own account, each backed up by matching UMFD/DWM session start noise
- Explained the one 4625 failure as a benign OS artifact rather than a real authentication failure, confirmed by both the event log timeline and Prefetch data
- Documented three explainable 4672 privilege events, while honestly noting the evidence window didn't capture a literal UAC click example
- Identified exactly three built in accounts responsible for all Logon Type 5 background noise
- Confirmed all twenty most executed programs on the machine run from legitimate locations
- Traced every genuinely flagged suspicious location execution across 459 prefetch records back to three real, explainable events, with only 14 of 1,703 seven day timeline entries flagged and none unexplained
- Extracted 141 thumbcache entries and reviewed three in depth, showing thumbcache can reveal content and document type independent of whether the file still exists
- Confirmed Chrome as the actively used browser and Edge as mostly idle, using both browser cache and Prefetch data independently
- Recovered original path, deletion time, and file status for all nineteen Recycle Bin entries, with thirteen still fully recoverable
- Traced the Opera browser installation across three separate artifact types (Prefetch, Recycle Bin, and the recoverable installer file), the clearest example in the whole investigation of why combining artifact types beats relying on just one

## Skills Demonstrated
- Live endpoint evidence handling, including working copies, hashing, and file count verification instead of touching artifacts directly
- Windows Security event log analysis and Logon Type interpretation
- Correlating privilege escalation events (4672) against process creation activity to find real causes
- Prefetch parsing and path recovery, including catching tool limitations by hand
- Thumbcache and browser cache analysis with responsible handling of personal content
- Manually parsing a binary file format (Recycle Bin $I files) against its fixed byte layout using PowerShell
- Cross artifact correlation to confirm the same event from multiple independent sources
- Honest documentation of gaps and limitations instead of forcing evidence to fit expectations

## Lessons Learned
- A Security log on even a single personal laptop is incredibly noisy, only six out of 24,699 events were the clean human unlock events I actually needed
- An analysis tool can silently damage evidence if you're not careful, the Excel corruption problem taught me the tool itself needs the same scrutiny as the original evidence
- A failure code you don't recognize should be looked up, not guessed at
- A forensic snapshot only tells you what happened up to the moment it was taken, my own PowerShell session for this exercise proved that directly
- A script running without an error doesn't mean it ran correctly, the FTK Imager path matching failure only showed up because I noticed something that should have been there was missing
- One real world event, like installing Opera, can show up scattered across many prefetch entries that look unrelated until you check their timestamps
- Combining artifact types gives you much stronger evidence than any single source, the Opera installation and the 13:01 lock screen window both proved this directly
- Working with thumbcache and browser cache felt different from log files because the content is immediately personal, which made me a lot more careful about what to actually include

## Future Improvements
- Go back and resolve the "time just went backwards" warning EvtxECmd raised during parsing
- Recheck other regex sensitive executable names that could silently break the same path matching technique that missed FTK Imager
- Review the remaining twelve thumbcache database files at other pixel sizes instead of only the 256px one
- Try EdgeCacheView again once its download page is reachable, for a slightly more native Edge cache parsing approach
- Capture a fresh, later Security log snapshot that actually includes this investigation session's own elevated terminal use, to get a real UAC click example for the privilege audit

## Resources
- Technical Report
- Screenshots
- LinkedIn Post
