# ClickFix Win+X Terminal-Paste Detection with Wazuh SIEM

## What is ClickFix?

ClickFix is a social engineering technique that presents a fake error, verification, or repair prompt and persuades a person to copy and paste a command into a Windows command interface. The page may make the action look like a normal way to solve a problem. If the person runs the pasted command, it can download and launch unwanted software. The critical step is the user's own paste and execution, which can make the activity look less like a conventional file download. [Microsoft Threat Intelligence](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/) documents this behavior; MITRE ATT&CK describes the related [Malicious Copy and Paste technique (T1204.004)](https://attack.mitre.org/techniques/T1204/004/).

## What is the Win+X terminal variant?

In the workflow reproduced here, the prompt tells the user to press **Win+X**, choose **Terminal** (the lab used **I**), and paste with **Ctrl+V**. This moves the suspicious text directly into Windows Terminal instead of the more familiar Win+R Run dialog. The lab screenshots show the verification prompt, terminal selection, endpoint observation, Windows event, and Wazuh alert. The pasted sample in the evidence contained a download-and-execution pattern; **do not run the pictured command**.

## Why we built this project

We wanted a repeatable way for the Cyber Range Fusion Center to observe this user-action stage **before command execution** and send the evidence to Wazuh. Our C# monitor checks a terminal paste, scores indicators in the clipboard text, and writes suspicious observations to the Windows Application log as **Event ID 2001**. Wazuh collects that event and custom **rule 110201** raises a level-12 alert for analyst review.

**What the demonstration proves:** suspicious text was pasted into a monitored terminal, Event ID 2001 was written, and Wazuh received an alert. The monitor does not independently record the Win+X keypress or prove that the pasted command executed.

## At a glance

| Role | Lab system |
| --- | --- |
| Windows test endpoint | Windows 11 Pro, `DESKTOP-EC88LQC`, Wazuh agent `002` |
| Wazuh manager | `sifat` |
| Endpoint project | [C# source and .NET project](src/ClickFixWinXMonitor/) |
| Wazuh configuration | [Agent collection block](config/wazuh-agent-ossec-fragment.xml) and [manager rule](config/clickfix_win_x_rules.xml) |
| Screenshots | [`evidence/`](evidence/) |

**Prerequisites:** .NET 8 SDK, an elevated PowerShell window on Windows, a connected Wazuh Windows agent, and access to the Wazuh manager. Use an isolated test machine and synthetic clipboard values.

## What the detection monitor can detect

The [C# monitor](src/ClickFixWinXMonitor/Program.cs) checks the clipboard **when Ctrl+V or Shift+Insert is pressed in a foreground terminal**. It supports Windows Terminal, PowerShell, pwsh, cmd, and conhost. Empty clipboard text and pastes into other apps are ignored. Each paste is scored, and **Event ID 2001 is written only when the risk score reaches at least 2**.

| Detection category | What it looks for |
| --- | --- |
| Numeric ClickFix value | Clipboard text consisting entirely of **2–15 digits**, such as `105567241`; adds score `2`. A single digit is outside the current rule. |
| PowerShell or shell indicators | `powershell`, `powershell.exe`, `pwsh`, `cmd /c`, `-nop`, `-noprofile`, `-enc`, `-encodedcommand`, `executionpolicy bypass`, `-ep bypass`, `-w hidden`, `windowstyle hidden`. |
| Download and execution tools | `Invoke-WebRequest`, `Invoke-RestMethod`, `DownloadString`, `DownloadFile`, `curl`, `wget`, `certutil`, `bitsadmin`, `mshta`, `rundll32`, `regsvr32`, `start-process`, `iex`, and `invoke-expression`. |
| Encoded PowerShell | PowerShell or pwsh with `-enc` / `-encodedcommand` followed by a long Base64-like argument; adds a separate score `4`. |
| Download plus execution chain | Both a download or URL indicator **and** an execution indicator in the same pasted text; adds score `4`. |
| Possible obfuscation | At least six of `^`, backtick, braces, or brackets, or a Base64-like sequence of at least 80 characters; adds score `3`. |
| Other contextual strings | `http://`, `https://`, `%temp%`, `\\appdata\\`, and `frombase64string` contribute to the score. |

The monitor adds weights for matched indicators. Scores **2–4 = MEDIUM**, **5–7 = HIGH**, and **8 or more = CRITICAL**. An Event ID 2001 includes the target process, paste method, matched indicators, risk score, time, host, a command preview capped at 2,048 characters, and the clipboard text's SHA-256 hash. A normal value such as `hello` has no matching indicator and produces no alert. Some legitimate administrative commands can match, so an analyst must review the event.

## Step 1 — See the simulated ClickFix instruction

The test page displayed a verification-style instruction. The lab user opened the terminal with **Win+X → I**, then pasted with **Ctrl+V**. You do not need to visit the pictured page to repeat the detection test; Step 4 provides harmless values.

![Verification-style instruction shown in the lab](evidence/clickfix-verification-instructions.png)

![Win+X menu and terminal selection](evidence/win-x-terminal-menu.png)

[View the original page screenshot](evidence/clickfix-lure-page.png)

## Step 2 — Create the Windows endpoint project

Open **PowerShell as Administrator** on the Windows endpoint. Confirm the SDK is installed with `dotnet --version`; install .NET 8 if it is missing. Create the project:

```powershell
cd C:\
mkdir ClickFixWinXAgent
cd ClickFixWinXAgent
dotnet new console -n ClickFixWinXMonitor
cd ClickFixWinXMonitor
dotnet add package System.Diagnostics.EventLog --version 8.0.1
```

Copy [`Program.cs`](src/ClickFixWinXMonitor/Program.cs) and [`ClickFixWinXMonitor.csproj`](src/ClickFixWinXMonitor/ClickFixWinXMonitor.csproj) from this repository into `C:\ClickFixWinXAgent\ClickFixWinXMonitor`, replacing the two generated files. The project targets `net8.0-windows` and enables Windows Forms for clipboard access.

Build and check the output:

```powershell
dotnet restore
dotnet build
```

**Expected:** `Build succeeded`, with no errors. This is the build output captured during the lab:

![Successful dotnet build](evidence/monitor-build-success.png)

## Step 3 — Register the Event Log source and run the tool

In elevated PowerShell, register the source once:

```powershell
if (-not [System.Diagnostics.EventLog]::SourceExists("ClickFixWinXMonitor")) {
    New-EventLog -LogName Application -Source ClickFixWinXMonitor
}
```

Publish the Windows executable:

```powershell
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

Start it from an elevated PowerShell window:

```powershell
Start-Process "C:\ClickFixWinXAgent\ClickFixWinXMonitor\bin\Release\net8.0-windows\win-x64\publish\ClickFixWinXMonitor.exe" -Verb RunAs
```

**Expected:** the monitor window says `Running`, `Event ID 2001`, minimum score `2`, and `Ctrl+V and Shift+Insert`. Keep this window open during the tests.

## Step 4 — Test the paste detection

Copy each value, open a terminal with **Win+X → I**, and paste with **Ctrl+V**. **Do not press Enter.** The monitor only emits Event ID 2001 when the clipboard content has a suspicious score of at least 2.

| Clipboard value | Expected monitor result |
| --- | --- |
| `105567241` | Numeric value of 2–15 digits; `MEDIUM`, score `2`, Event ID `2001` |
| `hello` | No suspicious indicator; no Event ID `2001` for this paste |
| `powershell -nop -w hidden https://example.invalid/test` | Multiple command indicators; warning Event ID `2001` |

The original lab used a command-like sample with `iex` and a download/execution pattern. Its monitor output showed **WindowsTerminal**, **Ctrl+V**, **HIGH**, and score **7**. The pictured command is evidence; do not execute it.

![Windows Terminal paste and monitor detection](evidence/terminal-paste-monitor.png)

[Close-up of the endpoint monitor result](evidence/endpoint-monitor-detection.png)

**How the tool works:** [`Program.cs`](src/ClickFixWinXMonitor/Program.cs) checks Ctrl+V or Shift+Insert while a supported terminal is in front, scores clipboard indicators, and writes suspicious results to the Application log. It does not alert on every clipboard change.

## Step 5 — Verify Event ID 2001 on Windows

Open **Event Viewer → Windows Logs → Application → Filter Current Log**, enter `2001`, and open an event whose source is `ClickFixWinXMonitor`. The event should show the target process, paste method, detection reason, risk score, and time.

Alternatively, use PowerShell:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = 'ClickFixWinXMonitor'
    Id           = 2001
} -MaxEvents 5 | Format-List TimeCreated, ProviderName, Id, LevelDisplayName, Message
```

This screenshot shows the lab's **Application / ClickFixWinXMonitor / Event ID 2001** warning:

![Windows Event Viewer showing Event ID 2001](evidence/windows-event-viewer-2001.png)

## Step 6 — Send the Windows event to Wazuh

On the **Windows endpoint**, open `C:\Program Files (x86)\ossec-agent\ossec.conf`. Inside its existing `<ossec_config>` section, add the [Application collection block](config/wazuh-agent-ossec-fragment.xml):

```xml
<localfile>
  <location>Application</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Keep all other agent configuration. Restart and verify the agent:

```powershell
Restart-Service -Name wazuh
Get-Service -Name wazuh
```

**Expected:** the agent is running and Wazuh can receive Windows Application events from agent `002`.

## Step 7 — Install custom rule 110201 on the Wazuh manager

On the **Linux Wazuh manager**, put [`config/clickfix_win_x_rules.xml`](config/clickfix_win_x_rules.xml) at:

```text
/var/ossec/etc/rules/clickfix_win_x_rules.xml
```

The lab rule matches provider `ClickFixWinXMonitor` plus Event ID `2001` and raises **rule 110201, level 12**. Test the rule and restart the manager:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
sudo systemctl is-active wazuh-manager
```

**Expected:** syntax check succeeds and the manager reports `active`. The rule file includes ATT&CK IDs `T1059.001` and `T1204.004` as the lab's mapping. A paste event alone does not confirm execution.

## Step 8 — Confirm the alert in the Wazuh dashboard

Repeat the suspicious paste test after the agent and manager are running. In Wazuh's alert Events view, filter for **rule.id `110201`** or **eventID `2001`**. Open the result and check:

| Field | Expected lab value |
| --- | --- |
| `agent.id` | `002` |
| `agent.name` | `DESKTOP-EC88LQC` |
| `data.win.system.channel` | `Application` |
| `data.win.system.eventID` | `2001` |
| `data.win.system.providerName` | `ClickFixWinXMonitor` |
| `rule.id` / `rule.level` | `110201` / `12` |

![Wazuh Events list with ClickFix alerts](evidence/wazuh-alerts-overview.png)

![Wazuh event showing agent, channel, and Event ID](evidence/wazuh-alert-document-details.png)

![Wazuh event showing the provider and decoder](evidence/wazuh-alert-fields.png)

![Wazuh event showing rule 110201 and level 12](evidence/wazuh-rule-110201-details.png)

## Result and limits

**Observed lab chain:** Win+X terminal workflow → suspicious paste detected → Windows Application Event ID 2001 → Wazuh agent 002 → custom rule 110201 → level 12 dashboard alert.

The event records a pasted command preview and hash. Use harmless data in the lab and restrict access to logs because clipboard contents may be sensitive. Confirm actual command execution separately with process, PowerShell, and network telemetry. The source and configuration here follow the supplied lab document; this repository has not been rebuilt on a Windows host during this update.
