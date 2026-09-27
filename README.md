# Detecting the Emerging ClickFix Win+X Terminal-Paste Phishing Variant with Wazuh SIEM

A Cyber Range Fusion Center detection use case for the ClickFix social engineering pattern in which a user is instructed to open a terminal from the Windows Win+X menu and paste clipboard content. A Windows endpoint monitor records the paste event, and Wazuh collects the resulting Windows Application log for analyst review.

> **Scope:** This project documents a lab detection of the Win+X → terminal → Ctrl+V workflow. A paste alert is a behavioral signal, not proof that a command executed or that the host was compromised.

## Detection flow

```text
ClickFix-style instruction → Win+X terminal launch → Ctrl+V paste
    → endpoint monitor → Windows Application Event ID 2001
    → Wazuh agent → Wazuh manager/dashboard alert → analyst review
```

## Lab environment

| Component | Lab configuration |
| --- | --- |
| Endpoint | Windows 11 Pro, `DESKTOP-EC88LQC` |
| Wazuh endpoint agent | Agent ID `002` |
| Manager | `sifat` |
| Endpoint monitor | .NET 8 Windows console application |
| Event source | Custom Windows Application event |
| Event ID | `2001` |

The agent was developed under `C:\ClickFixWinXAgent\ClickFixWinXMonitor` with `System.Diagnostics.EventLog` version `8.0.1`. The published target was `win-x64`, self-contained.

## What was verified

1. A user opened a terminal through Win+X and pasted test clipboard content with Ctrl+V.
2. The endpoint monitor generated Windows Application Event ID `2001` for the paste action, with context about the target process.
3. Wazuh agent `002` forwarded the event to the manager.
4. A corresponding Wazuh alert was visible in the dashboard.

The monitor was exercised with command-like text and numeric clipboard content. The event reports the observed paste; an analyst must assess the content and surrounding process activity. The exact published `Program.cs` and Wazuh configuration/rule XML should be added from the lab artifacts so the repository can serve as a reproducible implementation.

## Reproduction outline

1. Build and publish the Windows monitor on the test endpoint:
   ```powershell
   dotnet publish -c Release -r win-x64 --self-contained true
   ```
2. Start the published monitor from `bin\Release\net8.0-windows\win-x64\publish`.
3. Confirm the Wazuh agent is active and collecting the relevant Windows Application events.
4. Use harmless test clipboard text. Press Win+X, open the terminal, and paste with Ctrl+V. Do not execute untrusted clipboard content.
5. Check Event Viewer → Windows Logs → Application for Event ID `2001`.
6. Search the Wazuh dashboard for the same event and confirm the endpoint agent and timestamp.

## Detection evidence

The following screenshots are from the lab test. They show the endpoint observation, Event Viewer entry, and Wazuh alert. Some frames also contain a test command; do not execute clipboard content from screenshots.

| Step | Screenshot |
| --- | --- |
| Endpoint monitor detects a terminal paste | [Monitor detection](evidence/endpoint-monitor-detection.png) |
| Terminal and monitor together | [Terminal paste](evidence/terminal-paste-monitor.png) |
| Windows Application Event ID 2001 | [Event Viewer](evidence/windows-event-viewer-2001.png) |
| Alert appears in Wazuh | [Wazuh alerts overview](evidence/wazuh-alerts-overview.png) |
| Wazuh agent and event fields | [Wazuh document details](evidence/wazuh-alert-document-details.png) |
| Additional Wazuh event fields | [Wazuh alert fields](evidence/wazuh-alert-fields.png) |

### Endpoint detection

![Terminal paste detected by the endpoint monitor](evidence/terminal-paste-monitor.png)

### Windows Event Viewer

![Windows Application Event ID 2001](evidence/windows-event-viewer-2001.png)

### Wazuh SIEM alert

![ClickFix paste alert in Wazuh](evidence/wazuh-alerts-overview.png)

The screenshots document the successful test. A sanitized event JSON, exact monitor source, and Wazuh rule/configuration are still needed for full reproduction.

## Limitations

- Pasting alone does not establish command execution.
- Benign terminal pastes may produce the same behavioral event; severity depends on content and corroborating telemetry.
- The monitor must be running, and the Wazuh agent must collect the Application log for this signal to reach the SIEM.
- This README describes the observed lab flow; it does not substitute for the original source code and rules.

## Suggested MITRE ATT&CK mapping

ClickFix typically uses user interaction and command execution. Map the *observed behavior* to the relevant ATT&CK technique only after confirming which terminal, command, and execution path occurred. The paste event by itself supports investigation of a social engineering workflow, not a confirmed execution technique.

## Project status

**Endpoint event and Wazuh alert verified in the lab.** Screenshot evidence is published. Source and rule files are pending publication.
