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
| [`evidence/`](evidence/) | Six screenshots of the monitor, Event Viewer, and Wazuh |

## Lab environment

| Item | Value |
| --- | --- |
| Windows endpoint | Windows 11 Pro, `DESKTOP-EC88LQC` (`10.0.2.15` in the lab) |
| Wazuh agent | `002` |
| Wazuh manager | `sifat` |
| Monitor | C# / .NET 8, `System.Diagnostics.EventLog` 8.0.1 |
| Event source / channel / ID | `ClickFixWinXMonitor` / `Application` / `2001` |
| Detection phase | Terminal paste before execution |

## Step 1 — Prepare the Windows monitor project

On the Windows test endpoint, open **PowerShell as Administrator** and create the project directory:

```powershell
New-Item -ItemType Directory -Force -Path C:\ClickFixWinXAgent\ClickFixWinXMonitor
Set-Location C:\ClickFixWinXAgent\ClickFixWinXMonitor
dotnet new console --framework net8.0
dotnet add package System.Diagnostics.EventLog --version 8.0.1
```

Replace the generated `Program.cs` and project file with the two files from [`src/ClickFixWinXMonitor/`](src/ClickFixWinXMonitor/). The project targets `net8.0-windows` and enables Windows Forms for clipboard access. The source is the uploaded lab snapshot; the project file expresses its required target and package.

Register the custom Windows event source once with elevated PowerShell:

```powershell
if (-not [System.Diagnostics.EventLog]::SourceExists('ClickFixWinXMonitor')) {
    New-EventLog -LogName Application -Source ClickFixWinXMonitor
}
```

## Step 2 — Build, publish, and start the monitor

```powershell
Set-Location C:\ClickFixWinXAgent\ClickFixWinXMonitor
dotnet publish -c Release -r win-x64 --self-contained true
Set-Location .\bin\Release\net8.0-windows\win-x64\publish
.\ClickFixWinXMonitor.exe
```

The monitor prints its running status, Event ID `2001`, minimum risk score `2`, numeric range **2–15 digits**, and supported paste shortcuts **Ctrl+V** and **Shift+Insert**. It checks the foreground process against Windows Terminal, PowerShell, pwsh, cmd, and conhost.

**Build evidence:** ![Successful publish output](evidence/monitor-build-success.png)

## Step 3 — Reproduce a harmless terminal-paste test

1. Copy harmless test text such as `cmd /c echo ClickFix-Test`. The string scores `2` through the monitor's `cmd /c` indicator. **Copy only; do not run the command.**
2. Press **Win+X → I** to open the terminal on the test endpoint.
3. With the monitor still running, press **Ctrl+V** in the terminal. Do not press Enter.
4. Observe the monitor's suspicious terminal-paste message, including target process, paste method, risk score, and matched indicator.

The original lab screenshot used a command-like sample with `iex` and a download/execution-chain indicator. Treat that pictured command as evidence only; never run it.

![Monitor output during a terminal paste](evidence/terminal-paste-monitor.png)

[Additional monitor detection screenshot](evidence/endpoint-monitor-detection.png)

The code also detects 2–15 digit clipboard-only values, possible encoded PowerShell, download plus execution patterns, and simple obfuscation indicators. A match is a triage signal; an analyst must review false positives.

## Step 4 — Verify the Windows Application event

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

## Step 6 — Verify the Wazuh alert

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

The dashboard screenshots show a matching alert. The exact lab-side custom Wazuh rule XML is **not available**, so this repository does not claim a reproducible custom rule ID.

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

The lab produced a Windows warning event and a corresponding Wazuh alert for the ClickFix-style terminal-paste test. The source, project file, collection fragment, and six screenshots are available here for review. A confirmed MITRE ATT&CK execution mapping would require separate evidence that a pasted command actually ran.
