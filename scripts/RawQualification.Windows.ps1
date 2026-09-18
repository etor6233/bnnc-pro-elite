Set-StrictMode -Version Latest

function ConvertTo-RawQualificationCanonicalMode {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Production", "SevenDay", "Smoke", "Test")]
        [string] $Mode
    )
    switch ($Mode.ToLowerInvariant()) {
        "production" { return "Production" }
        "sevenday" { return "SevenDay" }
        "smoke" { return "Smoke" }
        "test" { return "Test" }
        default { throw "Unknown raw qualification mode." }
    }
}

function Get-RawQualificationGenerationScheduleClassification {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Production", "SevenDay", "Smoke", "Test")]
        [string] $Mode,
        [Parameter(Mandatory = $true)] [uint64] $Generations,
        [Parameter(Mandatory = $true)] [uint64] $Handovers,
        [Parameter(Mandatory = $true)] [uint64] $PlannedGenerationLaunches,
        [Parameter(Mandatory = $true)] [uint64] $ServerShutdownGenerationLaunches,
        [Parameter(Mandatory = $true)] [uint64] $ServerShutdownSupervisorEvents,
        [Parameter(Mandatory = $true)] [uint64] $ServerShutdownDurableEvents
    )
    $plannedTwoGeneration = (
        $Generations -eq 2 -and
        $Handovers -eq 1 -and
        $PlannedGenerationLaunches -eq 2 -and
        $ServerShutdownGenerationLaunches -eq 0 -and
        $ServerShutdownSupervisorEvents -eq 0 -and
        $ServerShutdownDurableEvents -eq 0)
    $plannedContinuousSevenDay = (
        $Mode -eq "SevenDay" -and
        $Generations -eq 8 -and
        $Handovers -eq 7 -and
        $PlannedGenerationLaunches -eq 8 -and
        $ServerShutdownGenerationLaunches -eq 0 -and
        $ServerShutdownSupervisorEvents -eq 0 -and
        $ServerShutdownDurableEvents -eq 0)
    if ($Mode -eq "SevenDay") {
        if ($plannedContinuousSevenDay) { return "PLANNED_CONTINUOUS_SEVEN_DAY" }
        return "DEVIATED"
    }
    if ($plannedTwoGeneration) { return "PLANNED_TWO_GENERATION" }
    if ($Mode -eq "Production") { return "DEVIATED" }
    return "NON_PRODUCTION_SCHEDULE"
}

function Get-RawQualificationRequiredTerminalTopology {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Production", "SevenDay", "Smoke", "Test")]
        [string] $Mode,
        [Parameter(Mandatory = $true)] [uint64] $TotalSeconds,
        [Parameter(Mandatory = $true)] [uint64] $RotationSeconds,
        [Parameter(Mandatory = $true)] [uint64] $OverlapSeconds,
        [Parameter(Mandatory = $true)] [uint64] $SegmentSeconds
    )
    if ($Mode -eq "Production") {
        if ($TotalSeconds -ne 86400 -or $RotationSeconds -ne 82800 -or
            $OverlapSeconds -ne 900 -or $SegmentSeconds -ne 900) {
            throw "ENDURANCE_24H topology requires exact 86400/82800/900/900 parameters."
        }
        return [pscustomobject][ordered]@{
            profile = "ENDURANCE_24H"
            required = $true
            generations = [uint64]2
            handovers = [uint64]1
            planned_generation_launches = [uint64]2
        }
    }
    if ($Mode -eq "SevenDay") {
        if ($TotalSeconds -ne 604800 -or $RotationSeconds -ne 82800 -or
            $OverlapSeconds -ne 900 -or $SegmentSeconds -ne 900) {
            throw "CONTINUOUS_7D topology requires exact 604800/82800/900/900 parameters."
        }
        return [pscustomobject][ordered]@{
            profile = "CONTINUOUS_7D"
            required = $true
            generations = [uint64]8
            handovers = [uint64]7
            planned_generation_launches = [uint64]8
        }
    }
    if ($Mode -eq "Smoke") {
        if ($TotalSeconds -ne 120 -or $RotationSeconds -ne 60 -or
            $OverlapSeconds -ne 10 -or $SegmentSeconds -ne 10) {
            throw "PUBLIC_SMOKE_120S topology requires exact 120/60/10/10 parameters."
        }
        return [pscustomobject][ordered]@{
            profile = "PUBLIC_SMOKE_120S"
            required = $true
            generations = [uint64]2
            handovers = [uint64]1
            planned_generation_launches = [uint64]2
        }
    }
    if ($Mode -eq "Test" -and
        $TotalSeconds -eq 7200 -and
        $RotationSeconds -eq 900 -and
        $OverlapSeconds -eq 900 -and
        $SegmentSeconds -eq 900) {
        return [pscustomobject][ordered]@{
            profile = "ROTATION_STRESS_120M"
            required = $true
            generations = [uint64]8
            handovers = [uint64]7
            planned_generation_launches = [uint64]8
        }
    }
    return [pscustomobject][ordered]@{
        profile = "AD_HOC_TEST"
        required = $false
        generations = [uint64]0
        handovers = [uint64]0
        planned_generation_launches = [uint64]0
    }
}

function Test-RawQualificationRequiredTerminalTopology {
    param(
        [Parameter(Mandatory = $true)] $Topology,
        [Parameter(Mandatory = $true)] [uint64] $Generations,
        [Parameter(Mandatory = $true)] [uint64] $Handovers,
        [Parameter(Mandatory = $true)] [uint64] $PlannedGenerationLaunches,
        [Parameter(Mandatory = $true)] [uint64] $ServerShutdownGenerationLaunches,
        [Parameter(Mandatory = $true)] [uint64] $ServerShutdownSupervisorEvents,
        [Parameter(Mandatory = $true)] [uint64] $ServerShutdownDurableEvents
    )
    if (-not [bool]$Topology.required) { return $true }
    return [bool](
        $Generations -eq [uint64]$Topology.generations -and
        $Handovers -eq [uint64]$Topology.handovers -and
        $PlannedGenerationLaunches -eq [uint64]$Topology.planned_generation_launches -and
        $ServerShutdownGenerationLaunches -eq 0 -and
        $ServerShutdownSupervisorEvents -eq 0 -and
        $ServerShutdownDurableEvents -eq 0)
}

function Initialize-RawQualificationNative {
    if (("RawQualificationNative" -as [type])) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

public sealed class RawQualificationLaunchResult
{
    public UInt32 ProcessId { get; internal set; }
    public string ExactCommandLine { get; internal set; }
    public Int64 CreationFileTimeUtc { get; internal set; }
    public IntPtr ProcessHandle { get; internal set; }
    public Int64 ResumeQpcTimestamp { get; internal set; }
}

public sealed class RawQualificationTreeDigestResult
{
    public UInt64 FileCount { get; internal set; }
    public UInt64 TotalBytes { get; internal set; }
    public string TreeSha256 { get; internal set; }
}

public sealed class RawQualificationPathIdentity
{
    public IntPtr Handle { get; internal set; }
    public UInt32 Attributes { get; internal set; }
    public UInt32 VolumeSerialNumber { get; internal set; }
    public UInt64 FileIndex { get; internal set; }
}

public sealed class RawQualificationJobQueryResult
{
    public bool Succeeded { get; internal set; }
    public UInt32 ActiveProcesses { get; internal set; }
    public UInt32 Error { get; internal set; }
}

public sealed class RawQualificationJobTerminationResult
{
    public bool Attempted { get; internal set; }
    public bool Succeeded { get; internal set; }
    public UInt32 Error { get; internal set; }
}

public sealed class RawQualificationLengthLimitedStream : Stream
{
    private readonly Stream inner;
    private readonly bool leaveOpen;
    private long remaining;

    public RawQualificationLengthLimitedStream(Stream inner, long length, bool leaveOpen)
    {
        if (inner == null) throw new ArgumentNullException("inner");
        if (!inner.CanRead) throw new ArgumentException("The inner stream is not readable.", "inner");
        if (length < 0) throw new ArgumentOutOfRangeException("length");
        this.inner = inner;
        this.remaining = length;
        this.leaveOpen = leaveOpen;
    }

    public override bool CanRead { get { return true; } }
    public override bool CanSeek { get { return false; } }
    public override bool CanWrite { get { return false; } }
    public override long Length { get { throw new NotSupportedException(); } }
    public override long Position
    {
        get { throw new NotSupportedException(); }
        set { throw new NotSupportedException(); }
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (remaining == 0) return 0;
        int bounded = (int)Math.Min((long)count, remaining);
        int read = inner.Read(buffer, offset, bounded);
        if (read <= 0) throw new EndOfStreamException("The snapshotted journal prefix became unreadable.");
        remaining -= read;
        return read;
    }

    public override int ReadByte()
    {
        if (remaining == 0) return -1;
        int value = inner.ReadByte();
        if (value < 0) throw new EndOfStreamException("The snapshotted journal prefix became unreadable.");
        remaining--;
        return value;
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
    public override void SetLength(long value) { throw new NotSupportedException(); }
    public override void Write(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !leaveOpen) inner.Dispose();
        base.Dispose(disposing);
    }
}

public static class RawQualificationNative
{
    public const UInt32 ES_SYSTEM_REQUIRED = 0x00000001;
    public const UInt32 ES_CONTINUOUS = 0x80000000;
    private const UInt32 JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private const Int32 JobObjectExtendedLimitInformation = 9;
    private const UInt32 CREATE_SUSPENDED = 0x00000004;
    private const UInt32 CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const UInt32 CREATE_NO_WINDOW = 0x08000000;
    private const UInt32 STARTF_USESTDHANDLES = 0x00000100;
    private const UInt32 GENERIC_READ = 0x80000000;
    private const UInt32 GENERIC_WRITE = 0x40000000;
    private const UInt32 FILE_SHARE_READ = 0x00000001;
    private const UInt32 FILE_SHARE_WRITE = 0x00000002;
    private const UInt32 FILE_SHARE_DELETE = 0x00000004;
    private const UInt32 CREATE_NEW = 1;
    private const UInt32 OPEN_EXISTING = 3;
    private const UInt32 FILE_ATTRIBUTE_NORMAL = 0x00000080;
    private const UInt32 FILE_READ_ATTRIBUTES = 0x00000080;
    private const UInt32 FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    private const UInt32 FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    private const UInt32 FILE_FLAG_WRITE_THROUGH = 0x80000000;
    private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
    private const UInt32 JOB_OBJECT_TERMINATE = 0x0008;

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        public Int32 nLength;
        public IntPtr lpSecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public UInt32 dwX;
        public UInt32 dwY;
        public UInt32 dwXSize;
        public UInt32 dwYSize;
        public UInt32 dwXCountChars;
        public UInt32 dwYCountChars;
        public UInt32 dwFillAttribute;
        public UInt32 dwFlags;
        public UInt16 wShowWindow;
        public UInt16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public UInt32 dwProcessId;
        public UInt32 dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public UInt64 ReadOperationCount;
        public UInt64 WriteOperationCount;
        public UInt64 OtherOperationCount;
        public UInt64 ReadTransferCount;
        public UInt64 WriteTransferCount;
        public UInt64 OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BY_HANDLE_FILE_INFORMATION
    {
        public UInt32 FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public UInt32 VolumeSerialNumber;
        public UInt32 FileSizeHigh;
        public UInt32 FileSizeLow;
        public UInt32 NumberOfLinks;
        public UInt32 FileIndexHigh;
        public UInt32 FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public Int64 PerProcessUserTimeLimit;
        public Int64 PerJobUserTimeLimit;
        public UInt32 LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public UInt32 ActiveProcessLimit;
        public UIntPtr Affinity;
        public UInt32 PriorityClass;
        public UInt32 SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
    {
        public Int64 TotalUserTime;
        public Int64 TotalKernelTime;
        public Int64 ThisPeriodTotalUserTime;
        public Int64 ThisPeriodTotalKernelTime;
        public UInt32 TotalPageFaultCount;
        public UInt32 TotalProcesses;
        public UInt32 ActiveProcesses;
        public UInt32 TotalTerminatedProcesses;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr attributes, string name);

    [DllImport("kernel32.dll")]
    private static extern void SetLastError(UInt32 errorCode);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenJobObject(UInt32 desiredAccess, bool inheritHandle, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(
        IntPtr job,
        Int32 informationClass,
        ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION information,
        UInt32 informationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryInformationJobObject(
        IntPtr job,
        Int32 informationClass,
        out JOBOBJECT_BASIC_ACCOUNTING_INFORMATION information,
        UInt32 informationLength,
        out UInt32 returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool TerminateJobObject(IntPtr job, UInt32 exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr handle);

    public static bool CloseRetainedProcessHandle(RawQualificationLaunchResult launch)
    {
        if (launch == null)
            throw new ArgumentNullException("launch");
        if (launch.ProcessHandle == IntPtr.Zero)
            throw new InvalidOperationException("Retained process handle is already closed");
        IntPtr handle = launch.ProcessHandle;
        if (!CloseHandle(handle))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CloseHandle retained process failed");
        // The setter is intentionally internal: only the native ownership
        // helper that performed the successful close may invalidate it.
        launch.ProcessHandle = IntPtr.Zero;
        return true;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern UInt32 ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(
        IntPtr process,
        out Int64 creationTime,
        out Int64 exitTime,
        out Int64 kernelTime,
        out Int64 userTime);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern UInt32 WaitForSingleObject(IntPtr handle, UInt32 milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(IntPtr process, out UInt32 exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr process, UInt32 exitCode);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessW(
        string applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
        UInt32 creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref STARTUPINFO startupInfo,
        out PROCESS_INFORMATION processInformation);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFileW(
        string fileName,
        UInt32 desiredAccess,
        UInt32 shareMode,
        ref SECURITY_ATTRIBUTES securityAttributes,
        UInt32 creationDisposition,
        UInt32 flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        IntPtr file,
        out BY_HANDLE_FILE_INFORMATION information);

    [DllImport("kernel32.dll")]
    public static extern UInt32 SetThreadExecutionState(UInt32 executionState);

    private static string QuoteArgument(string value)
    {
        if (value.Length > 0 && value.IndexOfAny(new char[] { ' ', '\t', '\n', '\v', '"' }) < 0)
            return value;
        StringBuilder output = new StringBuilder();
        output.Append('"');
        int backslashes = 0;
        foreach (char character in value)
        {
            if (character == '\\')
            {
                backslashes++;
                continue;
            }
            if (character == '"')
            {
                output.Append('\\', backslashes * 2 + 1);
                output.Append('"');
                backslashes = 0;
                continue;
            }
            output.Append('\\', backslashes);
            backslashes = 0;
            output.Append(character);
        }
        output.Append('\\', backslashes * 2);
        output.Append('"');
        return output.ToString();
    }

    private static string BuildCommandLine(string executable, string[] arguments)
    {
        StringBuilder commandLine = new StringBuilder(QuoteArgument(executable));
        foreach (string argument in arguments)
        {
            commandLine.Append(' ');
            commandLine.Append(QuoteArgument(argument));
        }
        return commandLine.ToString();
    }

    public static string BuildExactCommandLine(string executable, string[] arguments)
    {
        return BuildCommandLine(executable, arguments ?? new string[0]);
    }

    public static string QuoteExactArgument(string value)
    {
        if (value == null) throw new ArgumentNullException("value");
        return QuoteArgument(value);
    }

    private static IntPtr BuildEnvironmentBlock(string[] entries)
    {
        if (entries == null) return IntPtr.Zero;
        string[] sorted = (string[])entries.Clone();
        Array.Sort(sorted, StringComparer.OrdinalIgnoreCase);
        string previousName = null;
        StringBuilder block = new StringBuilder();
        foreach (string entry in sorted)
        {
            if (String.IsNullOrEmpty(entry) || entry.IndexOf('\0') >= 0)
                throw new ArgumentException("Environment entries must be non-empty and cannot contain NUL.", "entries");
            int separator = entry.IndexOf('=');
            if (separator <= 0)
                throw new ArgumentException("Environment entries must use NAME=value form.", "entries");
            string name = entry.Substring(0, separator);
            if (previousName != null && StringComparer.OrdinalIgnoreCase.Equals(previousName, name))
                throw new ArgumentException("Environment entries contain a duplicate name.", "entries");
            previousName = name;
            block.Append(entry);
            block.Append('\0');
        }
        block.Append('\0');
        return Marshal.StringToHGlobalUni(block.ToString());
    }

    public static IntPtr CreateKillOnCloseJob(string name)
    {
        SetLastError(0);
        IntPtr job = CreateJobObject(IntPtr.Zero, name);
        int createError = Marshal.GetLastWin32Error();
        if (job == IntPtr.Zero)
            throw new Win32Exception(createError, "CreateJobObject failed");
        if (createError != 0)
        {
            CloseHandle(job);
            string message = createError == 183
                ? "CreateJobObject opened an existing named Job"
                : "CreateJobObject returned a handle with unexpected last-error state";
            throw new Win32Exception(createError, message);
        }
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION information = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        UInt32 size = (UInt32)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, ref information, size))
        {
            int error = Marshal.GetLastWin32Error();
            CloseHandle(job);
            throw new Win32Exception(error, "SetInformationJobObject failed");
        }
        return job;
    }

    public static IntPtr OpenExistingJobForTerminate(string name)
    {
        IntPtr job = OpenJobObject(JOB_OBJECT_TERMINATE, false, name);
        if (job == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenJobObject failed");
        return job;
    }

    public static UInt32 GetActiveProcessCount(IntPtr job)
    {
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION information;
        UInt32 returned;
        UInt32 size = (UInt32)Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
        if (!QueryInformationJobObject(job, 1, out information, size, out returned))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "QueryInformationJobObject failed");
        return information.ActiveProcesses;
    }

    // These two helpers deliberately never throw.  They are used by the
    // launcher's first-chance failure path, where the Job must be queried and
    // terminated before any potentially blocking evidence I/O.  Last-error is
    // captured immediately after the native call that produced it.
    public static RawQualificationJobQueryResult TryGetActiveProcessCountNoThrow(IntPtr job)
    {
        RawQualificationJobQueryResult result = new RawQualificationJobQueryResult();
        if (job == IntPtr.Zero)
        {
            result.Succeeded = false;
            result.ActiveProcesses = 0;
            result.Error = 6; // ERROR_INVALID_HANDLE: no native call was attempted.
            return result;
        }
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION information;
        UInt32 returned;
        UInt32 size = (UInt32)Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
        bool succeeded = QueryInformationJobObject(job, 1, out information, size, out returned);
        Int32 error = succeeded ? 0 : Marshal.GetLastWin32Error();
        result.Succeeded = succeeded;
        result.ActiveProcesses = succeeded ? information.ActiveProcesses : 0;
        result.Error = succeeded ? 0U : unchecked((UInt32)error);
        return result;
    }

    public static RawQualificationJobTerminationResult TryTerminateJobObjectNoThrow(IntPtr job, UInt32 exitCode)
    {
        RawQualificationJobTerminationResult result = new RawQualificationJobTerminationResult();
        if (job == IntPtr.Zero)
        {
            result.Attempted = false;
            result.Succeeded = false;
            result.Error = 6; // ERROR_INVALID_HANDLE: no native call was attempted.
            return result;
        }
        result.Attempted = true;
        bool succeeded = TerminateJobObject(job, exitCode);
        Int32 error = succeeded ? 0 : Marshal.GetLastWin32Error();
        result.Succeeded = succeeded;
        result.Error = succeeded ? 0U : unchecked((UInt32)error);
        return result;
    }

    public static RawQualificationLaunchResult StartSuspendedInJobsRetainedWithEnvironment(
        IntPtr primaryJob,
        IntPtr secondaryJob,
        string executable,
        string[] arguments,
        string workingDirectory,
        string stdoutPath,
        string stderrPath,
        string[] environmentEntries)
    {
        SECURITY_ATTRIBUTES security = new SECURITY_ATTRIBUTES();
        security.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
        security.bInheritHandle = true;
        IntPtr stdoutHandle = INVALID_HANDLE_VALUE;
        IntPtr stderrHandle = INVALID_HANDLE_VALUE;
        IntPtr stdinHandle = INVALID_HANDLE_VALUE;
        PROCESS_INFORMATION process = new PROCESS_INFORMATION();
        bool created = false;
        IntPtr environmentBlock = IntPtr.Zero;
        try
        {
            UInt32 sharing = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
            UInt32 outputFlags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH;
            stdoutHandle = CreateFileW(stdoutPath, GENERIC_WRITE, sharing, ref security, CREATE_NEW, outputFlags, IntPtr.Zero);
            if (stdoutHandle == INVALID_HANDLE_VALUE)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "create stdout log failed");
            stderrHandle = CreateFileW(stderrPath, GENERIC_WRITE, sharing, ref security, CREATE_NEW, outputFlags, IntPtr.Zero);
            if (stderrHandle == INVALID_HANDLE_VALUE)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "create stderr log failed");
            stdinHandle = CreateFileW("NUL", GENERIC_READ, sharing, ref security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
            if (stdinHandle == INVALID_HANDLE_VALUE)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "open NUL stdin failed");

            STARTUPINFO startup = new STARTUPINFO();
            startup.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            startup.dwFlags = STARTF_USESTDHANDLES;
            startup.hStdInput = stdinHandle;
            startup.hStdOutput = stdoutHandle;
            startup.hStdError = stderrHandle;
            string exactCommandLine = BuildCommandLine(executable, arguments);
            StringBuilder mutableCommandLine = new StringBuilder(exactCommandLine);
            environmentBlock = BuildEnvironmentBlock(environmentEntries);
            UInt32 creationFlags = CREATE_SUSPENDED | CREATE_NO_WINDOW;
            if (environmentEntries != null) creationFlags |= CREATE_UNICODE_ENVIRONMENT;
            if (!CreateProcessW(
                executable,
                mutableCommandLine,
                IntPtr.Zero,
                IntPtr.Zero,
                true,
                creationFlags,
                environmentBlock,
                workingDirectory,
                ref startup,
                out process))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessW failed");
            }
            created = true;
            if (!AssignProcessToJobObject(primaryJob, process.hProcess))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "AssignProcessToJobObject primary failed");
            if (secondaryJob != IntPtr.Zero && !AssignProcessToJobObject(secondaryJob, process.hProcess))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "AssignProcessToJobObject nested secondary failed");
            Int64 creationTime;
            Int64 exitTime;
            Int64 kernelTime;
            Int64 userTime;
            if (!GetProcessTimes(process.hProcess, out creationTime, out exitTime, out kernelTime, out userTime))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "GetProcessTimes failed");
            Int64 resumeQpcTimestamp = Stopwatch.GetTimestamp();
            UInt32 resume = ResumeThread(process.hThread);
            if (resume == UInt32.MaxValue)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "ResumeThread failed");
            RawQualificationLaunchResult result = new RawQualificationLaunchResult();
            result.ProcessId = process.dwProcessId;
            result.ExactCommandLine = exactCommandLine;
            result.CreationFileTimeUtc = creationTime;
            result.ProcessHandle = process.hProcess;
            result.ResumeQpcTimestamp = resumeQpcTimestamp;
            process.hProcess = IntPtr.Zero;
            return result;
        }
        catch
        {
            if (created && process.hProcess != IntPtr.Zero)
                TerminateProcess(process.hProcess, 0xEE01);
            throw;
        }
        finally
        {
            if (process.hThread != IntPtr.Zero) CloseHandle(process.hThread);
            if (process.hProcess != IntPtr.Zero) CloseHandle(process.hProcess);
            if (stdinHandle != INVALID_HANDLE_VALUE) CloseHandle(stdinHandle);
            if (stderrHandle != INVALID_HANDLE_VALUE) CloseHandle(stderrHandle);
            if (stdoutHandle != INVALID_HANDLE_VALUE) CloseHandle(stdoutHandle);
            if (environmentBlock != IntPtr.Zero) Marshal.FreeHGlobal(environmentBlock);
        }
    }

    public static RawQualificationLaunchResult StartSuspendedInJobRetainedWithEnvironment(
        IntPtr job,
        string executable,
        string[] arguments,
        string workingDirectory,
        string stdoutPath,
        string stderrPath,
        string[] environmentEntries)
    {
        return StartSuspendedInJobsRetainedWithEnvironment(
            job, IntPtr.Zero, executable, arguments, workingDirectory,
            stdoutPath, stderrPath, environmentEntries);
    }

    public static RawQualificationLaunchResult StartSuspendedInJobRetained(
        IntPtr job,
        string executable,
        string[] arguments,
        string workingDirectory,
        string stdoutPath,
        string stderrPath)
    {
        return StartSuspendedInJobRetainedWithEnvironment(
            job, executable, arguments, workingDirectory, stdoutPath, stderrPath, null);
    }

    public static UInt32 StartSuspendedInJob(
        IntPtr job,
        string executable,
        string[] arguments,
        string workingDirectory,
        string stdoutPath,
        string stderrPath,
        out string exactCommandLine)
    {
        RawQualificationLaunchResult result = StartSuspendedInJobRetained(
            job, executable, arguments, workingDirectory, stdoutPath, stderrPath);
        exactCommandLine = result.ExactCommandLine;
        CloseHandle(result.ProcessHandle);
        return result.ProcessId;
    }

    public static UInt32 StartSuspendedInJobWithEnvironment(
        IntPtr job,
        string executable,
        string[] arguments,
        string workingDirectory,
        string stdoutPath,
        string stderrPath,
        string[] environmentEntries,
        out string exactCommandLine)
    {
        RawQualificationLaunchResult result = StartSuspendedInJobRetainedWithEnvironment(
            job, executable, arguments, workingDirectory, stdoutPath, stderrPath, environmentEntries);
        exactCommandLine = result.ExactCommandLine;
        CloseHandle(result.ProcessHandle);
        return result.ProcessId;
    }

    public static void TerminateProcessHandle(IntPtr process, UInt32 exitCode)
    {
        if (!TerminateProcess(process, exitCode))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "TerminateProcess failed");
    }

    public static bool WaitForProcessExit(IntPtr process, UInt32 milliseconds)
    {
        UInt32 result = WaitForSingleObject(process, milliseconds);
        if (result == 0) return true;
        if (result == 258) return false;
        throw new Win32Exception(Marshal.GetLastWin32Error(), "WaitForSingleObject failed");
    }

    public static UInt32 GetProcessExitCode(IntPtr process)
    {
        UInt32 exitCode;
        if (!GetExitCodeProcess(process, out exitCode))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "GetExitCodeProcess failed");
        return exitCode;
    }

    public static RawQualificationPathIdentity OpenPathIdentityNoFollow(
        string path,
        bool requireDirectory,
        bool denyDeleteSharing)
    {
        SECURITY_ATTRIBUTES security = new SECURITY_ATTRIBUTES();
        security.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
        UInt32 sharing = FILE_SHARE_READ | FILE_SHARE_WRITE;
        if (!denyDeleteSharing) sharing |= FILE_SHARE_DELETE;
        UInt32 flags = FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS;
        IntPtr handle = CreateFileW(
            path,
            FILE_READ_ATTRIBUTES,
            sharing,
            ref security,
            OPEN_EXISTING,
            flags,
            IntPtr.Zero);
        if (handle == INVALID_HANDLE_VALUE)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFileW path-identity open failed: " + path);
        try
        {
            BY_HANDLE_FILE_INFORMATION information;
            if (!GetFileInformationByHandle(handle, out information))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "GetFileInformationByHandle path identity failed: " + path);
            bool isDirectory = (information.FileAttributes & (UInt32)FileAttributes.Directory) != 0;
            if (requireDirectory && !isDirectory)
                throw new IOException("Path-identity open expected a directory: " + path);
            RawQualificationPathIdentity result = new RawQualificationPathIdentity();
            result.Handle = handle;
            result.Attributes = information.FileAttributes;
            result.VolumeSerialNumber = information.VolumeSerialNumber;
            result.FileIndex = ((UInt64)information.FileIndexHigh << 32) | information.FileIndexLow;
            handle = INVALID_HANDLE_VALUE;
            return result;
        }
        finally
        {
            if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
        }
    }

    private static string LowerHex(byte[] bytes)
    {
        StringBuilder output = new StringBuilder(bytes.Length * 2);
        foreach (byte value in bytes) output.Append(value.ToString("x2"));
        return output.ToString();
    }

    private static bool IsPythonRuntimeExtension(string path, bool topLevel)
    {
        string extension = Path.GetExtension(path).ToLowerInvariant();
        if (topLevel)
            return extension == ".exe" || extension == ".dll" || extension == ".zip";
        return extension == ".py" || extension == ".pyc" || extension == ".pyo" ||
            extension == ".pyd" || extension == ".dll" || extension == ".zip";
    }

    private static void EnumerateRuntimeDirectory(
        string baseRoot,
        string directory,
        List<string> output)
    {
        DirectoryInfo info = new DirectoryInfo(directory);
        if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Python runtime inventory rejects reparse-point directory: " + directory);
        foreach (string file in Directory.GetFiles(directory))
        {
            FileInfo fileInfo = new FileInfo(file);
            if ((fileInfo.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Python runtime inventory rejects reparse-point file: " + file);
            if (IsPythonRuntimeExtension(file, false)) output.Add(file);
        }
        foreach (string child in Directory.GetDirectories(directory))
        {
            if (String.Equals(Path.GetFileName(child), "site-packages", StringComparison.OrdinalIgnoreCase))
                continue;
            EnumerateRuntimeDirectory(baseRoot, child, output);
        }
    }

    private static List<string> EnumeratePythonRuntime(string baseRoot)
    {
        List<string> files = new List<string>();
        DirectoryInfo rootInfo = new DirectoryInfo(baseRoot);
        if ((rootInfo.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Python base runtime root cannot be a reparse point: " + baseRoot);
        foreach (string file in Directory.GetFiles(baseRoot))
        {
            FileInfo fileInfo = new FileInfo(file);
            if ((fileInfo.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Python runtime inventory rejects reparse-point file: " + file);
            if (IsPythonRuntimeExtension(file, true)) files.Add(file);
        }
        foreach (string name in new string[] { "DLLs", "Lib" })
        {
            string directory = Path.Combine(baseRoot, name);
            if (!Directory.Exists(directory))
                throw new DirectoryNotFoundException("Python base runtime directory is absent: " + directory);
            EnumerateRuntimeDirectory(baseRoot, directory, files);
        }
        string prefix = baseRoot.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        files.Sort(delegate(string left, string right) {
            string leftRelative = left.Substring(prefix.Length).Replace('\\', '/');
            string rightRelative = right.Substring(prefix.Length).Replace('\\', '/');
            return StringComparer.Ordinal.Compare(leftRelative, rightRelative);
        });
        for (int index = 1; index < files.Count; index++)
        {
            if (StringComparer.OrdinalIgnoreCase.Equals(files[index - 1], files[index]))
                throw new IOException("Python runtime inventory contains duplicate case-insensitive paths.");
        }
        return files;
    }

    public static RawQualificationTreeDigestResult HashPythonRuntimeTree(string baseRoot)
    {
        baseRoot = Path.GetFullPath(baseRoot).TrimEnd(Path.DirectorySeparatorChar);
        List<string> files = EnumeratePythonRuntime(baseRoot);
        if (files.Count == 0)
            throw new IOException("Python base runtime inventory is empty: " + baseRoot);
        string prefix = baseRoot + Path.DirectorySeparatorChar;
        UInt64 totalBytes = 0;
        using (SHA256 aggregate = SHA256.Create())
        using (MemoryStream material = new MemoryStream())
        {
            foreach (string file in files)
            {
                string relative = file.Substring(prefix.Length).Replace('\\', '/');
                byte[] digest;
                UInt64 length;
                using (FileStream stream = new FileStream(
                    file, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete,
                    1048576, FileOptions.SequentialScan))
                using (SHA256 sha = SHA256.Create())
                {
                    length = checked((UInt64)stream.Length);
                    digest = sha.ComputeHash(stream);
                }
                totalBytes = checked(totalBytes + length);
                string record = relative + "\0" + length.ToString(System.Globalization.CultureInfo.InvariantCulture) +
                    "\0" + LowerHex(digest) + "\n";
                byte[] recordBytes = Encoding.UTF8.GetBytes(record);
                material.Write(recordBytes, 0, recordBytes.Length);
            }
            List<string> verification = EnumeratePythonRuntime(baseRoot);
            if (verification.Count != files.Count)
                throw new IOException("Python runtime inventory changed while it was hashed.");
            for (int index = 0; index < files.Count; index++)
            {
                if (!StringComparer.Ordinal.Equals(files[index], verification[index]))
                    throw new IOException("Python runtime inventory changed while it was hashed.");
            }
            material.Position = 0;
            RawQualificationTreeDigestResult result = new RawQualificationTreeDigestResult();
            result.FileCount = checked((UInt64)files.Count);
            result.TotalBytes = totalBytes;
            result.TreeSha256 = LowerHex(aggregate.ComputeHash(material));
            return result;
        }
    }
}
'@ -Language CSharp -ErrorAction Stop
}

function Get-RawQualificationSha256Bytes {
    param([Parameter(Mandatory = $true)] [byte[]] $Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return (-join ($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString("x2") }))
    }
    finally {
        $sha.Dispose()
    }
}

function ConvertTo-RawQualificationExtendedLengthPath {
    param([Parameter(Mandatory = $true)] [string] $Path)
    $fullPath = [IO.Path]::GetFullPath($Path)
    if ($fullPath.StartsWith('\\?\UNC\', [StringComparison]::OrdinalIgnoreCase)) {
        return $fullPath
    }
    if ($fullPath.StartsWith('\\?\', [StringComparison]::Ordinal)) {
        if ($fullPath.Length -lt 7 -or $fullPath[5] -ne ':' -or $fullPath[6] -ne '\') {
            throw "Qualification I/O rejects unsupported Win32 device paths: $Path"
        }
        return $fullPath
    }
    if ($fullPath.StartsWith('\\', [StringComparison]::Ordinal)) {
        return '\\?\UNC\' + $fullPath.Substring(2)
    }
    if ($fullPath.Length -lt 3 -or $fullPath[1] -ne ':' -or $fullPath[2] -ne '\') {
        throw "Qualification I/O requires an absolute drive or UNC path: $Path"
    }
    return '\\?\' + $fullPath
}

function Get-RawQualificationSha256File {
    param([Parameter(Mandatory = $true)] [string] $Path)
    $stream = [IO.FileStream]::new(
        (ConvertTo-RawQualificationExtendedLengthPath -Path $Path),
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        ([IO.FileShare]::Read -bor [IO.FileShare]::Delete),
        1048576,
        [IO.FileOptions]::SequentialScan)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return (-join ($sha.ComputeHash($stream) | ForEach-Object { $_.ToString("x2") }))
    }
    finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}

function Assert-RawQualificationNoReparsePointInExistingPath {
    param([Parameter(Mandatory = $true)] [string] $Path)
    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $root = [IO.Path]::GetPathRoot($fullPath)
    if ([string]::IsNullOrWhiteSpace($root)) {
        throw "Cannot determine the filesystem root for path: $fullPath"
    }
    $current = $root
    $relative = $fullPath.Substring($root.Length)
    foreach ($component in @($relative -split '[\\/]' | Where-Object { $_.Length -gt 0 })) {
        $current = Join-Path $current $component
        try {
            $attributes = [IO.File]::GetAttributes(
                (ConvertTo-RawQualificationExtendedLengthPath -Path $current))
        }
        catch {
            $cause = $_.Exception
            while ($null -ne $cause.InnerException) { $cause = $cause.InnerException }
            if ($cause -is [IO.FileNotFoundException] -or $cause -is [IO.DirectoryNotFoundException]) {
                break
            }
            throw
        }
        if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Qualification evidence path rejects reparse points/junctions/symlinks: $current"
        }
        if (($attributes -band [IO.FileAttributes]::Directory) -eq 0 -and
            -not $current.Equals($fullPath, [StringComparison]::OrdinalIgnoreCase)) {
            throw "A non-directory path component blocks the qualification evidence root: $current"
        }
    }
    return $fullPath
}

function Get-RawQualificationSourceTreeDigest {
    param(
        [Parameter(Mandatory = $true)] [string] $Root,
        [switch] $AllowIgnoredBytecodeCaches
    )
    $resolved = (Resolve-Path -LiteralPath $Root -ErrorAction Stop).Path.TrimEnd('\')
    $cacheDirectories = @(Get-ChildItem -LiteralPath $resolved -Directory -Recurse -Force -ErrorAction Stop | Where-Object { $_.Name -eq "__pycache__" })
    $bytecodeFiles = @(Get-ChildItem -LiteralPath $resolved -File -Recurse -Force -ErrorAction Stop | Where-Object { $_.Extension -in @(".pyc", ".pyo") })
    if (-not $AllowIgnoredBytecodeCaches -and ($cacheDirectories.Count -ne 0 -or $bytecodeFiles.Count -ne 0)) {
        throw "Python verifier source must be source-only: reject __pycache__/.pyc/.pyo under $resolved"
    }
    $files = @(Get-ChildItem -LiteralPath $resolved -Filter "*.py" -File -Recurse -ErrorAction Stop)
    if ($files.Count -eq 0) { throw "Python verifier source tree is empty: $resolved" }
    $relativePaths = [string[]]@($files | ForEach-Object {
        $_.FullName.Substring($resolved.Length + 1).Replace('\', '/')
    })
    [Array]::Sort($relativePaths, [StringComparer]::Ordinal)
    $material = [Text.StringBuilder]::new()
    $inventory = @()
    foreach ($relative in $relativePaths) {
        $path = Join-Path $resolved $relative.Replace('/', '\')
        $hash = Get-RawQualificationSha256File -Path $path
        $length = [uint64](Get-Item -LiteralPath $path -ErrorAction Stop).Length
        $null = $material.Append($relative).Append("`0").Append($length).Append("`0").Append($hash).Append("`n")
        $inventory += [pscustomobject][ordered]@{
            path = $relative
            bytes = $length
            sha256 = $hash
        }
    }
    $digest = Get-RawQualificationSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($material.ToString()))
    return [pscustomobject][ordered]@{
        root = $resolved
        files = [uint64]$inventory.Count
        tree_sha256 = $digest
        inventory = $inventory
    }
}

function New-RawQualificationSealedSourceTree {
    param(
        [Parameter(Mandatory = $true)] $SourceTree,
        [Parameter(Mandatory = $true)] [string] $Destination
    )
    if ($null -eq $SourceTree -or
        $SourceTree.root -isnot [string] -or
        $SourceTree.tree_sha256 -isnot [string] -or
        $SourceTree.tree_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [uint64]$SourceTree.files -eq 0 -or
        @($SourceTree.inventory).Count -ne [uint64]$SourceTree.files) {
        throw "Sealed Python verifier source input is invalid."
    }
    $sourceRoot = (Resolve-Path -LiteralPath ([string]$SourceTree.root) -ErrorAction Stop).Path.TrimEnd('\')
    $destinationFull = [IO.Path]::GetFullPath($Destination).TrimEnd('\')
    if (Test-Path -LiteralPath $destinationFull) {
        throw "Sealed Python verifier destination already exists: $destinationFull"
    }
    $null = New-Item -ItemType Directory -Path $destinationFull -ErrorAction Stop
    $sourcePrefix = $sourceRoot + '\'
    $destinationPrefix = $destinationFull + '\'
    $orderedPaths = [string[]]@($SourceTree.inventory | ForEach-Object { [string]$_.path })
    $sortedPaths = [string[]]$orderedPaths.Clone()
    [Array]::Sort($sortedPaths, [StringComparer]::Ordinal)
    if (($orderedPaths -join "`n") -cne ($sortedPaths -join "`n")) {
        throw "Sealed Python verifier source inventory is not canonically ordered."
    }
    foreach ($row in @($SourceTree.inventory)) {
        $relative = [string]$row.path
        if ([string]::IsNullOrWhiteSpace($relative) -or
            [IO.Path]::IsPathRooted($relative) -or
            $relative -match '(^|[\\/])\.\.([\\/]|$)' -or
            $relative -notmatch '\.py$') {
            throw "Sealed Python verifier source inventory contains an unsafe path: $relative"
        }
        $sourcePath = [IO.Path]::GetFullPath((Join-Path $sourceRoot $relative.Replace('/', '\')))
        $destinationPath = [IO.Path]::GetFullPath((Join-Path $destinationFull $relative.Replace('/', '\')))
        if (-not $sourcePath.StartsWith($sourcePrefix, [StringComparison]::OrdinalIgnoreCase) -or
            -not $destinationPath.StartsWith($destinationPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
            throw "Sealed Python verifier source path escaped or disappeared: $relative"
        }
        $bytes = [IO.File]::ReadAllBytes((ConvertTo-RawQualificationExtendedLengthPath -Path $sourcePath))
        if ([uint64]$bytes.LongLength -ne [uint64]$row.bytes -or
            (Get-RawQualificationSha256Bytes -Bytes $bytes) -cne [string]$row.sha256) {
            throw "Python verifier source changed while its sealed copy was created: $relative"
        }
        $parent = Split-Path $destinationPath -Parent
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
            $null = New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop
        }
        Write-RawQualificationDurableNewFile -Path $destinationPath -Bytes $bytes
    }
    $sealed = Get-RawQualificationSourceTreeDigest -Root $destinationFull
    if ([uint64]$sealed.files -ne [uint64]$SourceTree.files -or
        [string]$sealed.tree_sha256 -cne [string]$SourceTree.tree_sha256) {
        throw "Sealed Python verifier source digest differs from its preflight input."
    }
    return $sealed
}

function Copy-RawQualificationVerifiedFile {
    param(
        [Parameter(Mandatory = $true)] [string] $Source,
        [Parameter(Mandatory = $true)] [string] $ExpectedSha256,
        [Parameter(Mandatory = $true)] [string] $Destination
    )
    if ($ExpectedSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw "Verified-file copy received an invalid expected digest."
    }
    $sourcePath = (Resolve-Path -LiteralPath $Source -ErrorAction Stop).Path
    $destinationPath = [IO.Path]::GetFullPath($Destination)
    if (Test-Path -LiteralPath $destinationPath) {
        throw "Verified-file destination already exists: $destinationPath"
    }
    $bytes = [IO.File]::ReadAllBytes((ConvertTo-RawQualificationExtendedLengthPath -Path $sourcePath))
    if ((Get-RawQualificationSha256Bytes -Bytes $bytes) -cne $ExpectedSha256) {
        throw "Source changed while its verified copy was created: $sourcePath"
    }
    $parent = Split-Path $destinationPath -Parent
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop
    }
    Write-RawQualificationDurableNewFile -Path $destinationPath -Bytes $bytes
    if ((Get-RawQualificationSha256File -Path $destinationPath) -cne $ExpectedSha256) {
        throw "Verified-file destination digest mismatch: $destinationPath"
    }
    return $destinationPath
}

function Get-RawQualificationPythonRuntimeDigest {
    param([Parameter(Mandatory = $true)] [string] $PythonExecutable)
    $venvPython = (Resolve-Path -LiteralPath $PythonExecutable -ErrorAction Stop).Path
    $venvRoot = [IO.Path]::GetFullPath((Join-Path (Split-Path $venvPython -Parent) ".."))
    $venvConfig = Join-Path $venvRoot "pyvenv.cfg"
    if (-not (Test-Path -LiteralPath $venvConfig -PathType Leaf)) {
        throw "Python runtime provenance lacks pyvenv.cfg: $venvConfig"
    }
    $configLines = @(Get-Content -LiteralPath $venvConfig -Encoding UTF8 -ErrorAction Stop)
    $configValues = @{}
    foreach ($line in $configLines) {
        if ($line -match '^\s*([^#=]+?)\s*=\s*(.*?)\s*$') {
            $key = $Matches[1].Trim().ToLowerInvariant()
            if ($configValues.ContainsKey($key)) { throw "Duplicate pyvenv.cfg key: $key" }
            $configValues[$key] = $Matches[2]
        }
    }
    if (-not $configValues.ContainsKey("home") -or -not $configValues.ContainsKey("executable")) {
        throw "pyvenv.cfg does not bind home and executable."
    }
    $baseRoot = [IO.Path]::GetFullPath([string]$configValues["home"]).TrimEnd('\')
    $baseExecutable = [IO.Path]::GetFullPath([string]$configValues["executable"])
    $basePrefix = $baseRoot + '\'
    if (-not $baseExecutable.StartsWith($basePrefix, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $baseExecutable -PathType Leaf)) {
        throw "pyvenv.cfg base executable escaped or is absent."
    }

    Initialize-RawQualificationNative
    $tree = [RawQualificationNative]::HashPythonRuntimeTree($baseRoot)
    return [pscustomobject][ordered]@{
        venv_root = $venvRoot
        venv_python = $venvPython
        venv_python_sha256 = Get-RawQualificationSha256File -Path $venvPython
        pyvenv_config = $venvConfig
        pyvenv_config_sha256 = Get-RawQualificationSha256File -Path $venvConfig
        base_root = $baseRoot
        base_executable = $baseExecutable
        base_executable_sha256 = Get-RawQualificationSha256File -Path $baseExecutable
        file_count = [uint64]$tree.FileCount
        total_bytes = [uint64]$tree.TotalBytes
        tree_sha256 = [string]$tree.TreeSha256
        included_extensions = @(".dll", ".exe", ".py", ".pyc", ".pyd", ".pyo", ".zip")
        excluded_path_components = @("site-packages")
    }
}

function ConvertTo-RawQualificationJsonBytes {
    param([Parameter(Mandatory = $true)] $Value, [switch] $Pretty)
    $json = if ($Pretty) {
        $Value | ConvertTo-Json -Depth 100
    }
    else {
        $Value | ConvertTo-Json -Depth 100 -Compress
    }
    return [Text.UTF8Encoding]::new($false).GetBytes($json + "`n")
}

function Write-RawQualificationDurableNewFile {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [byte[]] $Bytes
    )
    $stream = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::Read,
        4096,
        [IO.FileOptions]::WriteThrough)
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

function Write-RawQualificationDurableNewJson {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] $Value
    )
    $bytes = ConvertTo-RawQualificationJsonBytes -Value $Value -Pretty
    Write-RawQualificationDurableNewFile -Path $Path -Bytes $bytes
    return (Get-RawQualificationSha256Bytes -Bytes $bytes)
}

function New-RawQualificationJournal {
    param([Parameter(Mandatory = $true)] [string] $Path)
    $stream = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::Read,
        4096,
        [IO.FileOptions]::WriteThrough)
    return [pscustomobject]@{
        Path = $Path
        Stream = $stream
        NextIndex = [uint64]0
        Previous = ("0" * 64)
        Closed = $false
    }
}

function Get-RawQualificationJournalPrefixSnapshot {
    param([Parameter(Mandatory = $true)] $Journal)
    if ($null -eq $Journal -or $Journal.Closed -or $null -eq $Journal.Stream) {
        throw "Cannot snapshot a closed or absent qualification journal."
    }
    $stream = [IO.FileStream]$Journal.Stream
    if (-not $stream.CanRead -or -not $stream.CanWrite -or -not $stream.CanSeek) {
        throw "Qualification journal prefix snapshot requires one retained readable/writable/seekable handle."
    }
    $stream.Flush($true)
    $prefixLength = [long]$stream.Length
    if ($prefixLength -lt 0 -or $stream.Position -ne $prefixLength) {
        throw "Qualification journal write cursor is not at the exact durable prefix boundary."
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $stream.Position = 0
        $digest = $sha.ComputeHash($stream)
        if ($stream.Position -ne $prefixLength -or $stream.Length -ne $prefixLength) {
            throw "Qualification journal changed while its retained-handle prefix was hashed."
        }
        return [pscustomobject][ordered]@{
            file_bytes = [uint64]$prefixLength
            file_sha256 = -join ($digest | ForEach-Object { $_.ToString("x2") })
            records = [uint64]$Journal.NextIndex
            terminal_record_sha256 = [string]$Journal.Previous
        }
    }
    finally {
        $sha.Dispose()
        if ($stream.CanSeek) {
            $stream.Position = $prefixLength
        }
    }
}

function Add-RawQualificationJournalRecord {
    param(
        [Parameter(Mandatory = $true)] $Journal,
        [Parameter(Mandatory = $true)] [string] $Schema,
        [Parameter(Mandatory = $true)] [string] $Channel,
        [Parameter(Mandatory = $true)] [uint64] $WallNs,
        [Parameter(Mandatory = $true)] [uint64] $MonotonicTick,
        [Parameter(Mandatory = $true)] $Payload
    )
    if ($Journal.Closed) {
        throw "Journal is already closed: $($Journal.Path)"
    }
    $body = [ordered]@{
        schema = $Schema
        record_index = [uint64]$Journal.NextIndex
        wall_ns = $WallNs
        monotonic_tick = $MonotonicTick
        channel = $Channel
        payload = $Payload
        previous_record_sha256 = $Journal.Previous
    }
    $bodyJson = $body | ConvertTo-Json -Depth 100 -Compress
    $bodyBytes = [Text.UTF8Encoding]::new($false).GetBytes($bodyJson)
    $digest = Get-RawQualificationSha256Bytes -Bytes $bodyBytes
    $envelope = [ordered]@{
        body = $body
        record_sha256 = $digest
    }
    $bytes = ConvertTo-RawQualificationJsonBytes -Value $envelope
    $Journal.Stream.Write($bytes, 0, $bytes.Length)
    $Journal.Stream.Flush($true)
    $Journal.Previous = $digest
    $Journal.NextIndex = [uint64]($Journal.NextIndex + 1)
    return $digest
}

function Close-RawQualificationJournal {
    param([Parameter(Mandatory = $true)] $Journal)
    if (-not $Journal.Closed) {
        $Journal.Stream.Flush($true)
        $Journal.Stream.Dispose()
        $Journal.Closed = $true
    }
}

function Get-RawQualificationWallNs {
    $utc = [DateTimeOffset]::UtcNow
    return [uint64]($utc.ToUnixTimeMilliseconds() * 1000000)
}

function Test-RawQualificationDeadlineTicks {
    param(
        [Parameter(Mandatory = $true)] [ValidateRange(0, [long]::MaxValue)] [long] $ElapsedTicks,
        [Parameter(Mandatory = $true)] [ValidateRange(1, 604920)] [uint64] $TimeoutSeconds,
        [ValidateRange(1, [long]::MaxValue)] [long] $Frequency = [Diagnostics.Stopwatch]::Frequency
    )
    $deadlineTicks = [decimal]$TimeoutSeconds * [decimal]$Frequency
    return [decimal]$ElapsedTicks -le $deadlineTicks
}

function Test-RawQualificationJsonInteger {
    param(
        [Parameter(Mandatory = $true)] [AllowNull()] $Value,
        [decimal] $Minimum = [decimal]::MinValue,
        [decimal] $Maximum = [decimal]::MaxValue
    )
    if ($null -eq $Value) { return $false }
    $type = $Value.GetType()
    if ($type -notin @(
        [sbyte], [byte], [int16], [uint16], [int32], [uint32], [int64], [uint64])) {
        return $false
    }
    $numeric = [decimal]$Value
    return $numeric -ge $Minimum -and $numeric -le $Maximum
}

function Test-RawQualificationJsonBoolean {
    param([Parameter(Mandatory = $true)] [AllowNull()] $Value)
    return $null -ne $Value -and $Value.GetType() -eq [bool]
}

function Test-RawQualificationJsonString {
    param(
        [Parameter(Mandatory = $true)] [AllowNull()] $Value,
        [switch] $AllowEmpty
    )
    if ($null -eq $Value -or $Value.GetType() -ne [string]) { return $false }
    return $AllowEmpty -or -not [string]::IsNullOrWhiteSpace([string]$Value)
}

function Test-RawQualificationJsonSha256 {
    param([Parameter(Mandatory = $true)] [AllowNull()] $Value)
    return (Test-RawQualificationJsonString -Value $Value) -and
        [string]$Value -cmatch '^[0-9a-f]{64}$'
}

function Get-RawQualificationElapsedQpcTicks {
    param([Parameter(Mandatory = $true)] [long] $ResumeQpcTimestamp)
    $observed = [Diagnostics.Stopwatch]::GetTimestamp()
    if ($ResumeQpcTimestamp -le 0 -or $observed -lt $ResumeQpcTimestamp) {
        throw "Invalid pre-Resume QPC timestamp for bounded process accounting."
    }
    return [long]($observed - $ResumeQpcTimestamp)
}

function Convert-RawQualificationQpcTicksToMilliseconds {
    param(
        [Parameter(Mandatory = $true)] [ValidateRange(0, [long]::MaxValue)] [long] $ElapsedTicks,
        [ValidateRange(1, [long]::MaxValue)] [long] $Frequency = [Diagnostics.Stopwatch]::Frequency
    )
    return [uint64][decimal]::Floor(
        ([decimal]$ElapsedTicks * [decimal]1000) / [decimal]$Frequency)
}

function Convert-RawQualificationQpcTicksToWholeSeconds {
    param(
        [Parameter(Mandatory = $true)] [ValidateRange(0, [long]::MaxValue)] [long] $ElapsedTicks,
        [ValidateRange(1, [long]::MaxValue)] [long] $Frequency = [Diagnostics.Stopwatch]::Frequency
    )
    return [uint64][decimal]::Floor(
        [decimal]$ElapsedTicks / [decimal]$Frequency)
}

function Invoke-RawQualificationExplicitProcess {
    param(
        [Parameter(Mandatory = $true)] [string] $Executable,
        [Parameter(Mandatory = $true)] [string[]] $Arguments
    )
    $resolved = (Resolve-Path -LiteralPath $Executable -ErrorAction Stop).Path
    foreach ($argument in $Arguments) {
        if ([string]$argument -match '[\s"]') {
            throw "Explicit host-probe process arguments must be fixed tokens without whitespace or quotes."
        }
    }
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $resolved
    $start.Arguments = [string]::Join(" ", $Arguments)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw "Process.Start returned false for $resolved" }
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        return [pscustomobject]@{ exit_code = [int]$process.ExitCode; stdout = $stdout; stderr = $stderr }
    }
    finally { $process.Dispose() }
}

function Get-RawQualificationClockStatus {
    $maximumLastGoodSyncAgeSeconds = 21600.0
    $w32tm = Join-Path $env:SystemRoot "System32\w32tm.exe"
    if (-not (Test-Path -LiteralPath $w32tm -PathType Leaf)) { throw "Explicit w32tm.exe path is absent: $w32tm" }
    $query = Invoke-RawQualificationExplicitProcess -Executable $w32tm -Arguments ([string[]]@("/query", "/status", "/verbose"))
    $text = ([string]$query.stdout + [string]$query.stderr).Trim()
    $exitCode = [int]$query.exit_code
    $leap = if ($text -match '(?m)^Leap Indicator:\s*(\d+)') { [int]$Matches[1] } else { $null }
    $stratum = if ($text -match '(?m)^Stratum:\s*(\d+)') { [int]$Matches[1] } else { $null }
    $source = if ($text -match '(?m)^Source:\s*(.+?)\s*$') { $Matches[1].Trim() } else { $null }
    $lastSync = if ($text -match '(?m)^Last Successful Sync Time:\s*(.+?)\s*$') { $Matches[1].Trim() } else { $null }
    $rootDelay = if ($text -match '(?m)^Root Delay:\s*([-+0-9.eE]+)s') { [double]::Parse($Matches[1], [Globalization.CultureInfo]::InvariantCulture) } else { $null }
    $rootDispersion = if ($text -match '(?m)^Root Dispersion:\s*([-+0-9.eE]+)s') { [double]::Parse($Matches[1], [Globalization.CultureInfo]::InvariantCulture) } else { $null }
    $phaseOffset = if ($text -match '(?m)^Phase Offset:\s*([-+0-9.eE]+)s') { [double]::Parse($Matches[1], [Globalization.CultureInfo]::InvariantCulture) } else { $null }
    $secondsSinceGood = if ($text -match '(?m)^Time since Last Good Sync Time:\s*([-+0-9.eE]+)s') { [double]::Parse($Matches[1], [Globalization.CultureInfo]::InvariantCulture) } else { $null }
    $stateMachine = if ($text -match '(?m)^State Machine:\s*(\d+)') { [int]$Matches[1] } else { $null }
    $lastSyncError = if ($text -match '(?m)^Last Sync Error:\s*(\d+)') { [int]$Matches[1] } else { $null }
    $pollSeconds = if ($text -match '(?m)^Poll Interval:\s*\d+\s*\((\d+)s\)') { [uint64]$Matches[1] } else { $null }
    $localSource = $null -eq $source -or $source -match '(?i)Local CMOS|Free-running|VM IC Time Synchronization|unspecified'
    $healthy = $exitCode -eq 0 -and
        $leap -eq 0 -and
        $stratum -ge 1 -and $stratum -le 15 -and
        -not $localSource -and
        $stateMachine -eq 2 -and
        $lastSyncError -eq 0 -and
        $null -ne $secondsSinceGood -and
        $secondsSinceGood -ge 0 -and
        $secondsSinceGood -le $maximumLastGoodSyncAgeSeconds
    return [pscustomobject][ordered]@{
        healthy = [bool]$healthy
        leap_indicator = $leap
        stratum = $stratum
        source = $source
        last_successful_sync = $lastSync
        root_delay_s = $rootDelay
        root_dispersion_s = $rootDispersion
        phase_offset_s = $phaseOffset
        seconds_since_last_good_sync = $secondsSinceGood
        maximum_last_good_sync_age_s = $maximumLastGoodSyncAgeSeconds
        state_machine = $stateMachine
        last_sync_error = $lastSyncError
        poll_interval_s = $pollSeconds
        raw_status_sha256 = Get-RawQualificationSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($text))
        query_exit_code = $exitCode
    }
}

function Assert-RawQualificationClockHealthy {
    param([Parameter(Mandatory = $true)] $Clock)
    if (-not $Clock.healthy) {
        $violations = [Collections.Generic.List[string]]::new()
        if ([int]$Clock.query_exit_code -ne 0) { $violations.Add("QUERY_EXIT_NONZERO") }
        if ($null -eq $Clock.leap_indicator -or [int]$Clock.leap_indicator -ne 0) { $violations.Add("LEAP_INDICATOR_NOT_ZERO") }
        if ($null -eq $Clock.stratum -or [int]$Clock.stratum -lt 1 -or [int]$Clock.stratum -gt 15) { $violations.Add("STRATUM_OUT_OF_RANGE") }
        if ([string]::IsNullOrWhiteSpace([string]$Clock.source) -or
            [string]$Clock.source -match '(?i)Local CMOS|Free-running|VM IC Time Synchronization|unspecified') {
            $violations.Add("SOURCE_LOCAL_OR_UNSPECIFIED")
        }
        if ($null -eq $Clock.state_machine -or [int]$Clock.state_machine -ne 2) { $violations.Add("STATE_MACHINE_NOT_SYNC") }
        if ($null -eq $Clock.last_sync_error -or [int]$Clock.last_sync_error -ne 0) { $violations.Add("LAST_SYNC_ERROR_NONZERO") }
        if ($null -eq $Clock.seconds_since_last_good_sync -or
            [double]$Clock.seconds_since_last_good_sync -lt 0 -or
            [double]$Clock.seconds_since_last_good_sync -gt [double]$Clock.maximum_last_good_sync_age_s) {
            $violations.Add("LAST_GOOD_SYNC_ABSENT_STALE_OR_NEGATIVE")
        }
        if ($violations.Count -eq 0) { $violations.Add("HEALTH_FLAG_CONTRADICTS_PARSED_FIELDS") }
        $observation = $Clock | ConvertTo-Json -Depth 5 -Compress
        throw "HOST_CLOCK_HEALTH_GATE_FAILED: violations=$([string]::Join(',', $violations)); observation=$observation"
    }
}

function Read-RawQualificationNewUtf8Lines {
    param([Parameter(Mandatory = $true)] $State)
    if (-not (Test-Path -LiteralPath $State.Path -PathType Leaf)) {
        return @()
    }
    $stream = [IO.FileStream]::new(
        $State.Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try {
        if ($stream.Length -lt $State.Offset) {
            throw "Log length regressed: $($State.Path)"
        }
        $null = $stream.Seek($State.Offset, [IO.SeekOrigin]::Begin)
        $remaining = [int64]($stream.Length - $State.Offset)
        if ($remaining -eq 0) {
            return @()
        }
        if ($remaining -gt 16777216) {
            throw "More than 16 MiB accumulated between log polls: $($State.Path)"
        }
        $bytes = New-Object byte[] ([int]$remaining)
        $readTotal = 0
        while ($readTotal -lt $bytes.Length) {
            $read = $stream.Read($bytes, $readTotal, $bytes.Length - $readTotal)
            if ($read -eq 0) { break }
            $readTotal += $read
        }
        $State.Offset = [int64]($State.Offset + $readTotal)
        $text = $State.Partial + [Text.UTF8Encoding]::new($false, $true).GetString($bytes, 0, $readTotal)
        $parts = $text -split "`n", -1
        $State.Partial = $parts[$parts.Count - 1]
        if ($parts.Count -le 1) { return @() }
        return @($parts[0..($parts.Count - 2)] | ForEach-Object { $_.TrimEnd("`r") })
    }
    finally {
        $stream.Dispose()
    }
}

function Get-RawQualificationProcessIdentity {
    param(
        [Parameter(Mandatory = $true)] [uint32] $ProcessId,
        [Parameter(Mandatory = $true)] [string] $ExpectedExecutable,
        [Parameter(Mandatory = $true)] [string] $ExpectedCommandLine
    )
    $cim = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction Stop
    if ($null -eq $cim) {
        throw "Process $ProcessId disappeared before its identity was recorded."
    }
    $actualPath = [IO.Path]::GetFullPath([string]$cim.ExecutablePath)
    $expectedPath = [IO.Path]::GetFullPath($ExpectedExecutable)
    if (-not $actualPath.Equals($expectedPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Process $ProcessId executable identity differs from the release artifact."
    }
    if ([string]$cim.CommandLine -ne $ExpectedCommandLine) {
        throw "Process $ProcessId command line differs from the suspended launch contract."
    }
    $process = Get-Process -Id $ProcessId -ErrorAction Stop
    return [pscustomobject][ordered]@{
        pid = $ProcessId
        creation_time_utc = $process.StartTime.ToUniversalTime().ToString("o")
        executable_path = $actualPath
        executable_sha256 = Get-RawQualificationSha256File -Path $actualPath
        command_line = [string]$cim.CommandLine
    }
}

function Test-RawQualificationProcessIdentity {
    param([Parameter(Mandatory = $true)] $Identity)
    $cim = Get-CimInstance Win32_Process -Filter "ProcessId=$($Identity.pid)" -ErrorAction SilentlyContinue
    if ($null -eq $cim) {
        return [pscustomobject]@{ running = $false; valid = $true; reason = "exited" }
    }
    $pathEqual = [string]$cim.ExecutablePath -and
        [IO.Path]::GetFullPath([string]$cim.ExecutablePath).Equals(
            [IO.Path]::GetFullPath([string]$Identity.executable_path),
            [StringComparison]::OrdinalIgnoreCase)
    $commandEqual = [string]$cim.CommandLine -eq [string]$Identity.command_line
    $process = Get-Process -Id ([int]$Identity.pid) -ErrorAction SilentlyContinue
    $creationEqual = $null -ne $process -and
        $process.StartTime.ToUniversalTime().ToString("o") -eq [string]$Identity.creation_time_utc
    return [pscustomobject]@{
        running = $true
        valid = [bool]($pathEqual -and $commandEqual -and $creationEqual)
        reason = if ($pathEqual -and $commandEqual -and $creationEqual) { "exact" } else { "identity-mismatch" }
    }
}

function Get-RawQualificationNetworkCounters {
    $statistics = @(Get-NetAdapterStatistics -ErrorAction Stop)
    $sum = [ordered]@{
        received_bytes = [uint64]0
        sent_bytes = [uint64]0
        received_packets = [uint64]0
        sent_packets = [uint64]0
        received_discards = [uint64]0
        outbound_discards = [uint64]0
        received_errors = [uint64]0
        outbound_errors = [uint64]0
    }
    foreach ($item in $statistics) {
        $sum.received_bytes = [uint64]($sum.received_bytes + [uint64]$item.ReceivedBytes)
        $sum.sent_bytes = [uint64]($sum.sent_bytes + [uint64]$item.SentBytes)
        $sum.received_packets = [uint64]($sum.received_packets + [uint64]$item.ReceivedUnicastPackets + [uint64]$item.ReceivedBroadcastPackets + [uint64]$item.ReceivedMulticastPackets)
        $sum.sent_packets = [uint64]($sum.sent_packets + [uint64]$item.SentUnicastPackets + [uint64]$item.SentBroadcastPackets + [uint64]$item.SentMulticastPackets)
        $sum.received_discards = [uint64]($sum.received_discards + [uint64]$item.ReceivedDiscardedPackets)
        $sum.outbound_discards = [uint64]($sum.outbound_discards + [uint64]$item.OutboundDiscardedPackets)
        $sum.received_errors = [uint64]($sum.received_errors + [uint64]$item.ReceivedPacketErrors)
        $sum.outbound_errors = [uint64]($sum.outbound_errors + [uint64]$item.OutboundPacketErrors)
    }
    return [pscustomobject]$sum
}

function Get-RawQualificationDiskCounters {
    param([Parameter(Mandatory = $true)] [string] $DriveDeviceId)
    $logical = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$DriveDeviceId'" -ErrorAction Stop
    if ($null -eq $logical) { throw "Logical disk $DriveDeviceId is unavailable." }
    $counter = Get-Counter -Counter @(
        '\PhysicalDisk(_Total)\Avg. Disk sec/Read',
        '\PhysicalDisk(_Total)\Avg. Disk sec/Write',
        '\PhysicalDisk(_Total)\Current Disk Queue Length'
    ) -ErrorAction Stop
    $values = @($counter.CounterSamples)
    return [pscustomobject][ordered]@{
        device_id = $DriveDeviceId
        filesystem = [string]$logical.FileSystem
        size_bytes = [uint64]$logical.Size
        free_bytes = [uint64]$logical.FreeSpace
        avg_read_latency_s = [double]$values[0].CookedValue
        avg_write_latency_s = [double]$values[1].CookedValue
        current_queue_length = [double]$values[2].CookedValue
    }
}

function Get-RawQualificationCollectorProcesses {
    param([Parameter(Mandatory = $true)] [uint32[]] $RootProcessIds)
    $all = @(Get-CimInstance Win32_Process -ErrorAction Stop)
    $selected = New-Object 'System.Collections.Generic.HashSet[uint32]'
    $roots = New-Object 'System.Collections.Generic.HashSet[uint32]'
    foreach ($root in $RootProcessIds) {
        $null = $selected.Add($root)
        $null = $roots.Add($root)
    }
    $changed = $true
    while ($changed) {
        $changed = $false
        foreach ($process in $all) {
            if ($selected.Contains([uint32]$process.ParentProcessId) -and -not $selected.Contains([uint32]$process.ProcessId)) {
                $null = $selected.Add([uint32]$process.ProcessId)
                $changed = $true
            }
        }
    }
    $result = @()
    foreach ($snapshotProcess in $all | Where-Object { $selected.Contains([uint32]$_.ProcessId) }) {
        $process = $snapshotProcess
        $processId = [uint32]$snapshotProcess.ProcessId
        $hasStableIdentity = $null -ne $snapshotProcess.CreationDate -and
            -not [string]::IsNullOrWhiteSpace([string]$snapshotProcess.Name) -and
            -not [string]::IsNullOrWhiteSpace([string]$snapshotProcess.ExecutablePath)
        if (-not $hasStableIdentity) {
            # Win32_Process enumeration can retain a just-exited descendant long enough to
            # return its PID/name while identity fields such as ExecutablePath are already
            # unavailable. Re-read the PID once. A vanished non-root is outside this sample;
            # a live but unidentifiable process (or an unidentifiable root) is fail-closed.
            $refreshed = @(Get-CimInstance Win32_Process -Filter "ProcessId=$processId" -ErrorAction SilentlyContinue)
            if ($refreshed.Count -ne 1) {
                if ($roots.Contains($processId)) {
                    throw "Required collector root process $processId vanished during telemetry sampling."
                }
                continue
            }
            if ($null -eq $snapshotProcess.CreationDate -or
                $null -eq $refreshed[0].CreationDate -or
                ([DateTime]$snapshotProcess.CreationDate).ToUniversalTime().Ticks -ne
                    ([DateTime]$refreshed[0].CreationDate).ToUniversalTime().Ticks) {
                if ($roots.Contains($processId)) {
                    throw "Required collector root process $processId changed identity during telemetry sampling."
                }
                continue
            }
            $process = $refreshed[0]
            $hasStableIdentity = -not [string]::IsNullOrWhiteSpace([string]$process.Name) -and
                -not [string]::IsNullOrWhiteSpace([string]$process.ExecutablePath)
            if (-not $hasStableIdentity) {
                throw "Live collector descendant process $processId has no stable executable identity."
            }
        }
        $result += [pscustomobject][ordered]@{
            pid = $processId
            parent_pid = [uint32]$process.ParentProcessId
            name = [string]$process.Name
            creation_date = if ($null -ne $process.CreationDate) { ([DateTime]$process.CreationDate).ToUniversalTime().ToString("o") } else { $null }
            executable_path = [string]$process.ExecutablePath
            cpu_kernel_100ns = [uint64]$process.KernelModeTime
            cpu_user_100ns = [uint64]$process.UserModeTime
            working_set_bytes = [uint64]$process.WorkingSetSize
            page_file_kib = [uint64]$process.PageFileUsage
            handles = [uint32]$process.HandleCount
            read_operations = [uint64]$process.ReadOperationCount
            read_bytes = [uint64]$process.ReadTransferCount
            write_operations = [uint64]$process.WriteOperationCount
            write_bytes = [uint64]$process.WriteTransferCount
        }
    }
    return @($result | Sort-Object pid)
}

function Test-RawQualificationTcpPort {
    param(
        [Parameter(Mandatory = $true)] [string] $HostName,
        [Parameter(Mandatory = $true)] [int] $Port,
        [int] $TimeoutMilliseconds = 10000
    )
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $async = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMilliseconds, $false)) {
            return $false
        }
        $client.EndConnect($async)
        return $client.Connected
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}
