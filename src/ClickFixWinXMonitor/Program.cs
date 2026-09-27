using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

internal class Program
{
    private const string EventSource =
        "ClickFixWinXMonitor";

    private const int EventId = 2001;

    private const int VK_CONTROL = 0x11;
    private const int VK_SHIFT = 0x10;
    private const int VK_INSERT = 0x2D;
    private const int VK_V = 0x56;

    private static bool _pasteWasDown;

    private static readonly string[] TerminalProcesses =
    {
        "windowsterminal",
        "powershell",
        "pwsh",
        "cmd",
        "conhost"
    };

    private static readonly Dictionary<string, int>
        Indicators =
            new(StringComparer.OrdinalIgnoreCase)
            {
                ["powershell"] = 1,
                ["powershell.exe"] = 1,
                ["pwsh"] = 1,
                ["cmd /c"] = 2,

                ["-encodedcommand"] = 4,
                ["-enc"] = 3,
                ["-nop"] = 2,
                ["-noprofile"] = 1,
                ["executionpolicy bypass"] = 3,
                ["-ep bypass"] = 3,

                ["windowstyle hidden"] = 3,
                ["-w hidden"] = 3,

                ["invoke-expression"] = 4,
                ["iex"] = 3,
                ["invoke-webrequest"] = 2,
                ["invoke-restmethod"] = 2,
                ["downloadstring"] = 4,
                ["downloadfile"] = 4,
                ["frombase64string"] = 4,

                ["curl "] = 2,
                ["curl.exe"] = 2,
                ["wget "] = 2,

                ["certutil"] = 3,
                ["bitsadmin"] = 4,
                ["mshta"] = 4,
                ["rundll32"] = 3,
                ["regsvr32"] = 4,

                ["start-process"] = 2,
                ["%temp%"] = 1,
                ["\\appdata\\"] = 1,

                ["http://"] = 2,
                ["https://"] = 2
            };

    [DllImport("user32.dll")]
    private static extern short GetAsyncKeyState(
        int virtualKey);

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(
        IntPtr windowHandle,
        out uint processId);

    [STAThread]
    private static void Main()
    {
        Console.Title =
            "ClickFix Win X Detection Monitor";

        Console.ForegroundColor =
            ConsoleColor.Cyan;

        Console.WriteLine(
            "============================================");

        Console.WriteLine(
            " ClickFix Win X Detection Monitor");

        Console.WriteLine(
            "============================================");

        Console.ResetColor();

        Console.WriteLine(
            "Monitor status     : Running");

        Console.WriteLine(
            "Event source       : ClickFixWinXMonitor");

        Console.WriteLine(
            "Detection event ID : 2001");

        Console.WriteLine(
            "Minimum risk score : 2");

        Console.WriteLine(
            "Numeric detection  : 2 to 15 digits");

        Console.WriteLine(
            "Monitoring period  : Continuous");

        Console.WriteLine(
            "Paste methods      : Ctrl+V and Shift+Insert");

        Console.WriteLine();

        Console.WriteLine(
            "Press Ctrl + C to stop the monitor.");

        Console.WriteLine();

        while (true)
        {
            try
            {
                MonitorTerminalPaste();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor =
                    ConsoleColor.Yellow;

                Console.WriteLine(
                    $"Monitor error: {ex.Message}");

                Console.ResetColor();
            }

            Thread.Sleep(40);
        }
    }

    private static void MonitorTerminalPaste()
    {
        bool ctrlV =
            IsKeyDown(VK_CONTROL) &&
            IsKeyDown(VK_V);

        bool shiftInsert =
            IsKeyDown(VK_SHIFT) &&
            IsKeyDown(VK_INSERT);

        bool pasteIsDown =
            ctrlV ||
            shiftInsert;

        /*
         * Only process the first key-down state.
         * Holding Ctrl+V will not continuously repeat.
         */
        if (pasteIsDown && !_pasteWasDown)
        {
            string foregroundProcess =
                GetForegroundProcessName();

            if (!IsTerminalProcess(foregroundProcess))
            {
                Console.ForegroundColor =
                    ConsoleColor.DarkGray;

                Console.WriteLine(
                    $"[{DateTime.Now:HH:mm:ss}] " +
                    $"Paste ignored. Foreground process: " +
                    $"{foregroundProcess}");

                Console.ResetColor();

                _pasteWasDown = pasteIsDown;
                return;
            }

            string pasteMethod =
                ctrlV
                    ? "Ctrl+V"
                    : "Shift+Insert";

            AnalyseClipboard(
                foregroundProcess,
                pasteMethod);
        }

        _pasteWasDown = pasteIsDown;
    }

    private static void AnalyseClipboard(
        string processName,
        string pasteMethod)
    {
        if (!Clipboard.ContainsText())
        {
            Console.ForegroundColor =
                ConsoleColor.DarkGray;

            Console.WriteLine(
                $"[{DateTime.Now:HH:mm:ss}] " +
                "Clipboard does not contain text.");

            Console.ResetColor();
            return;
        }

        string clipboardText =
            Clipboard.GetText().Trim();

        if (string.IsNullOrWhiteSpace(clipboardText))
        {
            Console.ForegroundColor =
                ConsoleColor.DarkGray;

            Console.WriteLine(
                $"[{DateTime.Now:HH:mm:ss}] " +
                "Empty clipboard text ignored.");

            Console.ResetColor();
            return;
        }

        List<string> matchedIndicators = new();
        int riskScore = 0;

        /*
         * Match known ClickFix indicators.
         */
        foreach (
            KeyValuePair<string, int> indicator
            in Indicators)
        {
            if (clipboardText.Contains(
                indicator.Key,
                StringComparison.OrdinalIgnoreCase))
            {
                matchedIndicators.Add(indicator.Key);
                riskScore += indicator.Value;
            }
        }

        /*
         * Detect values containing only
         * 2 to 15 numerical digits.
         */
        bool numericValue =
            Regex.IsMatch(
                clipboardText,
                @"^[0-9]{2,15}$");

        if (numericValue)
        {
            matchedIndicators.Add(
                "Numeric clipboard value containing " +
                "2 to 15 digits");

            riskScore += 2;
        }

        if (LooksLikeEncodedPowerShell(clipboardText))
        {
            matchedIndicators.Add(
                "Possible encoded PowerShell");

            riskScore += 4;
        }

        if (HasDownloadAndExecutionChain(clipboardText))
        {
            matchedIndicators.Add(
                "Download and execution chain");

            riskScore += 4;
        }

        if (LooksObfuscated(clipboardText))
        {
            matchedIndicators.Add(
                "Possible command obfuscation");

            riskScore += 3;
        }

        /*
         * Do not generate an Event when no suspicious
         * indicators are found or the score is below 2.
         */
        if (riskScore < 2)
        {
            Console.ForegroundColor =
                ConsoleColor.DarkGray;

            Console.WriteLine(
                $"[{DateTime.Now:HH:mm:ss}] " +
                "Terminal paste checked: " +
                "No suspicious indicator found.");

            Console.ResetColor();
            return;
        }

        string riskLevel =
            riskScore >= 8
                ? "CRITICAL"
                : riskScore >= 5
                    ? "HIGH"
                    : "MEDIUM";

        string clipboardHash =
            CalculateSha256(clipboardText);

        WriteDetectionEvent(
            clipboardText,
            processName,
            pasteMethod,
            matchedIndicators,
            clipboardHash,
            riskScore,
            riskLevel);
    }

    private static bool LooksLikeEncodedPowerShell(
        string text)
    {
        return Regex.IsMatch(
            text,
            @"(?i)(powershell|pwsh).*?" +
            @"-(enc|encodedcommand)\s+" +
            @"[A-Za-z0-9+/=]{20,}");
    }

    private static bool HasDownloadAndExecutionChain(
        string text)
    {
        bool downloadIndicator =
            Regex.IsMatch(
                text,
                @"(?i)(https?://|curl|wget|iwr|irm|" +
                @"invoke-webrequest|invoke-restmethod|" +
                @"downloadstring|downloadfile)");

        bool executionIndicator =
            Regex.IsMatch(
                text,
                @"(?i)(iex|invoke-expression|" +
                @"start-process|cmd\s*/c|powershell|" +
                @"pwsh|mshta|rundll32|regsvr32)");

        return
            downloadIndicator &&
            executionIndicator;
    }

    private static bool LooksObfuscated(
        string text)
    {
        int specialCharacterCount =
            text.Count(character =>
                character is '^'
                or '`'
                or '{'
                or '}'
                or '['
                or ']');

        bool excessiveSpecialCharacters =
            specialCharacterCount >= 6;

        bool longBase64LikeContent =
            Regex.IsMatch(
                text,
                @"[A-Za-z0-9+/=]{80,}");

        return
            excessiveSpecialCharacters ||
            longBase64LikeContent;
    }

    private static bool IsTerminalProcess(
        string processName)
    {
        return TerminalProcesses.Any(
            terminalProcess =>
                processName.Equals(
                    terminalProcess,
                    StringComparison.OrdinalIgnoreCase));
    }

    private static string GetForegroundProcessName()
    {
        IntPtr foregroundWindow =
            GetForegroundWindow();

        if (foregroundWindow == IntPtr.Zero)
        {
            return "Unknown";
        }

        GetWindowThreadProcessId(
            foregroundWindow,
            out uint processId);

        try
        {
            using Process process =
                Process.GetProcessById(
                    (int)processId);

            return process.ProcessName;
        }
        catch
        {
            return "Unknown";
        }
    }

    private static bool IsKeyDown(
        int virtualKey)
    {
        return
            (GetAsyncKeyState(virtualKey) & 0x8000)
            != 0;
    }

    private static string CalculateSha256(
        string text)
    {
        using SHA256 sha256 =
            SHA256.Create();

        byte[] textBytes =
            Encoding.UTF8.GetBytes(text);

        byte[] hashBytes =
            sha256.ComputeHash(textBytes);

        return Convert
            .ToHexString(hashBytes)
            .ToLowerInvariant();
    }

    private static string PrepareTextForLog(
        string text)
    {
        const int maximumLength = 2048;

        string singleLineText =
            text
                .Replace("\r", " ")
                .Replace("\n", " ");

        if (singleLineText.Length <= maximumLength)
        {
            return singleLineText;
        }

        return singleLineText[..maximumLength] +
               " [TRUNCATED]";
    }

    private static void WriteDetectionEvent(
        string clipboardText,
        string processName,
        string pasteMethod,
        List<string> matchedIndicators,
        string clipboardHash,
        int riskScore,
        string riskLevel)
    {
        string textForLog =
            PrepareTextForLog(clipboardText);

        string detectionReason =
            string.Join(
                ", ",
                matchedIndicators);

        string eventMessage = $"""
ClickFix Win X Terminal Paste Detection
Target Process: {processName}
Paste Method: {pasteMethod}
Detection Stage: Pre-Execution Paste
Detection Result: Suspicious
Detection Reason: {detectionReason}
Risk Level: {riskLevel}
Risk Score: {riskScore}
Matched Indicators: {detectionReason}
Clipboard Text: {textForLog}
Clipboard Length: {clipboardText.Length}
Clipboard SHA256: {clipboardHash}
Hostname: {Environment.MachineName}
Username: {Environment.UserName}
Timestamp: {DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}
Description: Suspicious ClickFix-style content was pasted into a monitored Windows terminal.
Detection Source: ClickFixWinXMonitor
""";

        try
        {
            EventLog.WriteEntry(
                EventSource,
                eventMessage,
                EventLogEntryType.Warning,
                EventId);

            Console.WriteLine();

            Console.ForegroundColor =
                ConsoleColor.Red;

            Console.WriteLine(
                "============================================");

            Console.WriteLine(
                " SUSPICIOUS TERMINAL PASTE DETECTED");

            Console.WriteLine(
                "============================================");

            Console.WriteLine(
                $"Event ID          : {EventId}");

            Console.WriteLine(
                $"Target Process    : {processName}");

            Console.WriteLine(
                $"Paste Method      : {pasteMethod}");

            Console.WriteLine(
                $"Risk Level        : {riskLevel}");

            Console.WriteLine(
                $"Risk Score        : {riskScore}");

            Console.WriteLine(
                $"Detection Reason  : {detectionReason}");

            Console.WriteLine(
                $"Matched Indicators: {detectionReason}");

            Console.WriteLine(
                "============================================");

            Console.ResetColor();
            Console.WriteLine();
        }
        catch (Exception ex)
        {
            Console.ForegroundColor =
                ConsoleColor.Yellow;

            Console.WriteLine(
                $"Event Log write failed: " +
                $"{ex.Message}");

            Console.WriteLine(
                "Run the monitor as Administrator and " +
                "confirm the Event Source exists.");

            Console.ResetColor();
        }
    }
}