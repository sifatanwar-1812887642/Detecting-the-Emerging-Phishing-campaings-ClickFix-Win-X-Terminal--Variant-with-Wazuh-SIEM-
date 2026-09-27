# Detecting the Emerging ClickFix Win+X Terminal-Paste Phishing Variant with Wazuh SIEM

**Cyber Range Fusion Center | Windows endpoint detection → Windows Event Log → Wazuh SIEM**

This lab reproduces the user-interaction stage of a ClickFix-style lure: the user is directed to open a terminal through **Win+X → I** and paste clipboard content. A C# endpoint monitor scores the pasted text and writes suspicious terminal-paste observations to the Windows **Application** log as **Event ID 2001**. The Wazuh agent collects the event, and the alert appears in the Wazuh dashboard.

> The monitor observes a paste into a supported terminal process. It does **not** independently record the Win+X keystroke or prove that the pasted content ran. Screenshots document the lab workflow; Event ID 2001 means a suspicious *pre-execution paste*.

## Repository map

| Path | Purpose |
| --- | --- |
| [`src/ClickFixWinXMonitor/Program.cs`](src/ClickFixWinXMonitor/Program.cs) | Original endpoint monitor source supplied during this lab |
| [`src/ClickFixWinXMonitor/ClickFixWinXMonitor.csproj`](src/ClickFixWinXMonitor/ClickFixWinXMonitor.csproj) | .NET 8 Windows project and EventLog dependency |
| [`config/wazuh-agent-ossec-fragment.xml`](config/wazuh-agent-ossec-fragment.xml) | Application event-channel collection block for the Windows agent |
| [`config/clickfix_win_x_rules.xml`](config/clickfix_win_x_rules.xml) | Custom Wazuh rule `110201` from the lab guide |
| [`evidence/`](evidence/) | Eleven screenshots covering the lure, Win+X menu, build, monitor, Event Viewer, and Wazuh |

## Lab environment

| Item | Value |
| --- | --- |
| Windows endpoint | Windows 11 Pro, `DESKTOP-EC88LQC` (`10.0.2.15` in the lab) |
| Wazuh agent | `002` |
| Wazuh manager | `sifat` |
| Monitor | C# / .NET 8, `System.Diagnostics.EventLog` 8.0.1 |
| Event source / channel / ID | `ClickFixWinXMonitor` / `Application` / `2001` |
| Detection phase | Terminal paste before execution |

## Step 0 — Scenario shown in the lab

A browser page presented a verification-style prompt with keyboard instructions. The user followed the **Win+X → I → Ctrl+V** path on the Windows endpoint. These are screenshots of the test setup, not an instruction to visit or trust the pictured page:

![Verification-style ClickFix page](evidence/clickfix-verification-instructions.png)

![Win+X terminal selection](evidence/win-x-terminal-menu.png)

[Original page screenshot](evidence/clickfix-lure-page.png)

## Step 1 — Prepare the Windows monitor project

On the Windows test endpoint, open **PowerShell as Administrator** and create the project directory:

```powershell
New-Item -ItemType Directory -Force -Path C:\ClickFixWinXAgent\ClickFixWinXMonitor
Set-Location C:\ClickFixWinXAgent\ClickFixWinXMonitor
dotnet new console --framework net8.0
dotnet add package System.Diagnostics.EventLog --version 8.0.1
```

Replace the generated `Program.cs` and project file with the two files from [`src/ClickFixWinXMonitor/`](src/ClickFixWinXMonitor/). The project targets `net8.0-windows` and enables Windows Forms for clipboard access. The source and project settings are transcribed from the supplied Win+X lab document.

Restore and build in the project directory:

```powershell
dotnet restore
dotnet build
```

The lab guide records **Build succeeded, 0 warnings, 0 errors**. Register the custom Windows event source once with elevated PowerShell:

```powershell
if (-not [System.Diagnostics.EventLog]::SourceExists('ClickFixWinXMonitor')) {
    New-EventLog -LogName Application -Source ClickFixWinXMonitor
}
```

## Step 2 — Build, publish, and start the monitor

```powershell
Set-Location C:\ClickFixWinXAgent\ClickFixWinXMonitor
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
Set-Location .\bin\Release\net8.0-windows\win-x64\publish
.\ClickFixWinXMonitor.exe
```

The monitor prints its running status, Event ID `2001`, minimum risk score `2`, numeric range **2–15 digits**, and supported paste shortcuts **Ctrl+V** and **Shift+Insert**. It checks the foreground process against Windows Terminal, PowerShell, pwsh, cmd, and conhost.

**Build evidence:** ![Successful dotnet build output](evidence/monitor-build-success.png)

## Step 3 — Run the lab checks

**Numeric test:** Copy `105567241`, press Win+X → I, and paste with Ctrl+V without pressing Enter. The code scores a 2–15 digit value as `MEDIUM` with score `2`, producing Event ID `2001`.

**Benign test:** Copy `hello` and paste into the terminal. It should report no suspicious indicator and should not write Event ID `2001`.

**Command-indicator test:** Copy `powershell -nop -w hidden https://example.invalid/test` and paste without pressing Enter. This synthetic string matches several indicators. Do not execute it.

For a shorter command-like test:

1. Copy harmless test text such as `cmd /c echo ClickFix-Test`. The string scores `2` through the monitor's `cmd /c` indicator. **Copy only; do not run the command.**
2. Press **Win+X → I** to open the terminal on the test endpoint.
3. With the monitor still running, press **Ctrl+V** in the terminal. Do not press Enter.
4. Observe the monitor's suspicious terminal-paste message, including target process, paste method, risk score, and matched indicator.

The original lab screenshot used a command-like sample with `iex` and a download/execution-chain indicator. Treat that pictured command as evidence only; never run it.

![Monitor output during a terminal paste](evidence/terminal-paste-monitor.png)

[Additional monitor detection screenshot](evidence/endpoint-monitor-detection.png)

The code also detects 2–15 digit clipboard-only values, possible encoded PowerShell, download plus execution patterns, and simple obfuscation indicators. A match is a triage signal; an analyst must review false positives.

## Step 4 — Verify the Windows Application event

For a PowerShell check:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = 'ClickFixWinXMonitor'
    Id           = 2001
} -MaxEvents 5 | Format-List TimeCreated, ProviderName, Id, LevelDisplayName, Message
```

Open **Event Viewer → Windows Logs → Application** and filter for **Event ID 2001** or source `ClickFixWinXMonitor`. Open a matching warning and inspect the target process, paste method, detection stage, reason, risk score, timestamp, and host. The event message also records a truncated clipboard preview and SHA-256 hash, so avoid putting secrets in the clipboard during testing.

![Application Event ID 2001 in Event Viewer](evidence/windows-event-viewer-2001.png)

The pictured event shows `WindowsTerminal`, `Ctrl+V`, `Pre-Execution Paste`, and a `HIGH` risk score of `7`.

## Step 5 — Configure Wazuh agent collection

On the Windows endpoint, add the [Application event-channel block](config/wazuh-agent-ossec-fragment.xml) **inside the existing** `<ossec_config>` element of:

```text
C:\Program Files (x86)\ossec-agent\ossec.conf
```

Then restart and verify the agent:

```powershell
Restart-Service -Name wazuh
Get-Service -Name wazuh
```

The fragment in this repository is a collection example that matches the observed `Application` channel. Preserve the endpoint's other localfile entries. The exact full `ossec.conf` from the lab was not retained here.

## Step 6 — Add the custom Wazuh rule on the manager

The supplied lab guide places [`clickfix_win_x_rules.xml`](config/clickfix_win_x_rules.xml) at `/var/ossec/etc/rules/clickfix_win_x_rules.xml`. It matches provider `ClickFixWinXMonitor` and Event ID `2001`, inherits Windows event rule `60601`, and raises custom rule **110201** at level **12**. The rule contains ATT&CK IDs `T1059.001` and `T1204.004` as lab metadata; the paste alone does not prove PowerShell execution.

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
sudo systemctl is-active wazuh-manager
```

Run the syntax check before restarting. Preserve other custom rules on the manager.

## Step 7 — Verify the Wazuh alert

In the Wazuh dashboard, search the alert events for endpoint agent `002`, Event ID `2001`, or provider `ClickFixWinXMonitor`. Open the document and verify:

- `agent.name`: `DESKTOP-EC88LQC`
- `data.win.system.channel`: `Application`
- `data.win.system.eventID`: `2001`
- `data.win.system.providerName`: `ClickFixWinXMonitor`
- `data.win.eventdata.data`: monitor's detection message

![Wazuh alert overview](evidence/wazuh-alerts-overview.png)

| Detailed evidence | What it shows |
| --- | --- |
| [Wazuh document details](evidence/wazuh-alert-document-details.png) | Agent `002`, host, Application channel, Event ID `2001`, message |
| [Wazuh alert fields](evidence/wazuh-alert-fields.png) | Provider `ClickFixWinXMonitor`, warning severity, event-channel decoder |

The supplied alert JSON confirms rule **110201**, level **12**, description **ClickFix suspicious command pasted into Windows Terminal**, agent `002`, and Event ID `2001`.

![Wazuh custom rule details](evidence/wazuh-rule-110201-details.png)

## Detection logic and boundaries

```text
Win+X → terminal → paste
                   ↓
           foreground terminal check
                   ↓
        clipboard indicator scoring (minimum 2)
                   ↓
       Windows Application Event ID 2001
                   ↓
          Wazuh agent → SIEM alert
```

- The C# monitor polls paste key combinations and inspects text on the clipboard when a listed terminal is foreground. It does not continuously alert on every clipboard change.
- Risk levels in the source are `MEDIUM` (score 2–4), `HIGH` (5–7), and `CRITICAL` (8+). Below score 2, it logs no Event ID 2001.
- A pasted command is **not** proof of execution, persistence, download, or compromise. Correlate with process creation, PowerShell logging, and network telemetry before making those claims.
- Clipboard previews can contain sensitive text. Use synthetic test data and review event retention and access before using this monitor outside the lab.
- This is a lab snapshot. No Windows build was run from this repository in the current environment; the included screenshot shows the successful build on the test host.

## Outcome

The lab produced a Windows warning event and a corresponding Wazuh alert for the ClickFix-style terminal-paste test. The original monitor source, project settings, manager rule 110201, agent collection fragment, and eleven screenshots are available here. A confirmed MITRE ATT&CK execution finding requires separate evidence that the pasted command actually ran.
