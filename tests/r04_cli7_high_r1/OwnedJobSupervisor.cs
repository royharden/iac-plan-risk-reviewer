// SOURCE ONLY. No build, native load, fixture, or invocation is admitted.
// Framework/OS loader closure must be separately frozen before a build/run grant.
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

internal static class OwnedJobSupervisor
{
    private const uint Suspended = 0x4, UnicodeEnvironment = 0x400,
        ExtendedStartup = 0x80000, NoWindow = 0x08000000;
    private const uint WaitObject = 0, WaitTimeout = 258, Infinite = 0xffffffff;
    private const uint WriteAccess = 0x40000000, CreateNew = 1, Normal = 0x80;
    private const int StartUseHandles = 0x100;
    private static readonly IntPtr Invalid = new(-1);
    private static readonly IntPtr HandleListAttribute = new(0x20002);
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };
    private static FileStream? log;
    private static Stopwatch total = new();
    private static JsonElement config;
    private static string output = "";
    private static int watchdogFired;

    private sealed class Watchdog : IDisposable
    {
        private readonly Timer timer;
        internal Watchdog(IntPtr ownedJob, int seconds)
        {
            timer = new Timer(_ =>
            {
                Interlocked.Exchange(ref watchdogFired, 1);
                // Independent timer owner survives worker death and main-thread file I/O.
                // Only this still-live owned job handle; no file I/O on the timer thread.
                TerminateJobObject(ownedJob, 124);
            }, null, TimeSpan.FromSeconds(seconds), Timeout.InfiniteTimeSpan);
        }
        public void Dispose() => timer.DisposeAsync().AsTask().GetAwaiter().GetResult();
    }

    [StructLayout(LayoutKind.Sequential)] private struct SecurityAttributes
    { public int length; public IntPtr descriptor; public int inherit; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct StartupInfo
    {
        public int cb; public IntPtr reserved, desktop, title;
        public int x, y, xSize, ySize, xCount, yCount, fillAttribute, flags;
        public short showWindow, reserved2Size; public IntPtr reserved2, stdin, stdout, stderr;
    }
    [StructLayout(LayoutKind.Sequential)] private struct StartupInfoEx
    { public StartupInfo info; public IntPtr attributes; }
    [StructLayout(LayoutKind.Sequential)] private struct ProcessInformation
    { public IntPtr process, thread; public uint pid, tid; }
    [StructLayout(LayoutKind.Sequential)] private struct BasicLimits
    {
        public long processTime, jobTime; public uint flags; public UIntPtr minWorkingSet, maxWorkingSet;
        public uint activeProcessLimit; public UIntPtr affinity; public uint priorityClass, schedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)] private struct IoCounters
    { public ulong readOps, writeOps, otherOps, readBytes, writeBytes, otherBytes; }
    [StructLayout(LayoutKind.Sequential)] private struct ExtendedLimits
    { public BasicLimits basic; public IoCounters io; public UIntPtr processMemory, jobMemory, peakProcess, peakJob; }
    [StructLayout(LayoutKind.Sequential)] private struct Accounting
    {
        public long totalUser, totalKernel, periodUser, periodKernel;
        public uint pageFaults, totalProcesses, activeProcesses, terminatedProcesses;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObjectW(IntPtr attributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetInformationJobObject(
        IntPtr job, int informationClass, ref ExtendedLimits information, uint size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool QueryInformationJobObject(
        IntPtr job, int informationClass, out Accounting information, uint size, IntPtr returnedSize);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateJobObject(IntPtr job, uint exit);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessW(string application, StringBuilder command,
        IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint flags,
        IntPtr environment, string directory, ref StartupInfoEx startup, out ProcessInformation information);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateProcess(IntPtr process, uint exit);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetExitCodeProcess(IntPtr process, out uint exit);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CreatePipe(
        out IntPtr read, out IntPtr write, ref SecurityAttributes attributes, uint size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr CreateFileW(
        string name, uint access, uint sharing, ref SecurityAttributes attributes, uint creation,
        uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool InitializeProcThreadAttributeList(
        IntPtr list, int count, uint flags, ref UIntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool UpdateProcThreadAttribute(
        IntPtr list, uint flags, IntPtr attribute, IntPtr value, UIntPtr size, IntPtr previous, IntPtr returnedSize);
    [DllImport("kernel32.dll")] private static extern void DeleteProcThreadAttributeList(IntPtr list);

    private static void Check(bool condition, string operation)
    { if (!condition) throw new InvalidOperationException(operation + " Win32=" + Marshal.GetLastWin32Error()); }
    private static string Text(JsonElement node, string property) => node.GetProperty(property).GetString()!;
    private static string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
    private static string Ordinary(string path)
    {
        if (!Path.IsPathFullyQualified(path) || path.StartsWith(@"\\") || path[2..].Contains(':') ||
            path.Replace('/', '\\').Split('\\').Contains("..")) throw new IOException("plain absolute path required");
        path = Path.GetFullPath(path);
        for (string? p = path; p != null; p = Path.GetDirectoryName(p))
        {
            try { if ((File.GetAttributes(p) & FileAttributes.ReparsePoint) != 0) throw new IOException("reparse ancestry"); }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
        }
        return path;
    }
    private static void WriteNew(string path, object value)
    {
        Ordinary(path);
        using FileStream stream = new(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        JsonSerializer.Serialize(stream, value, JsonOptions); stream.Flush(true);
    }
    private static void Record(object value)
    {
        if (log == null) throw new IOException("receipt not open");
        byte[] bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value, JsonOptions) + "\n");
        log.Write(bytes); log.Flush(true); // Any failure halts launch/effects.
    }
    private static void Pins()
    {
        foreach (JsonElement row in config.GetProperty("pins").EnumerateArray())
        {
            string path = Ordinary(Text(row, "path"));
            if (new FileInfo(path).Length != row.GetProperty("bytes").GetInt64() || Hash(path) != Text(row, "sha256"))
                throw new IOException("pinned input drift: " + path);
        }
        foreach (JsonElement row in config.GetProperty("absent").EnumerateArray())
        {
            string path = Ordinary(row.GetString()!);
            if (File.Exists(path) || Directory.Exists(path)) throw new IOException("required startup absence drift");
        }
    }
    private static string Quote(string argument)
    {
        // Windows CommandLineToArgvW/CRT quoting, including trailing backslashes.
        StringBuilder result = new("\""); int slashes = 0;
        foreach (char character in argument)
        {
            if (character == '\\') { slashes++; continue; }
            if (character == '"') result.Append('\\', slashes * 2 + 1).Append('"');
            else result.Append('\\', slashes).Append(character);
            slashes = 0;
        }
        return result.Append('\\', slashes * 2).Append('"').ToString();
    }
    private sealed class Child : IDisposable
    {
        internal ProcessInformation info;
        internal string role = "", stdout = "", stderr = "", audit = "";
        public void Dispose() { CloseHandle(info.thread); CloseHandle(info.process); }
    }
    private static Child Start(IntPtr job, string role, int call)
    {
        Pins();
        string label = role == "worker" ? "worker" : $"cli-{call:00}";
        string prefix = Text(config.GetProperty("cache_prefixes"), label);
        Ordinary(prefix);
        if (File.Exists(prefix) || Directory.Exists(prefix)) throw new IOException("cache prefix occupied");
        string python = Text(config, "interpreter"), bootstrap = Text(config, "bootstrap");
        Child child = new() { role = role, stdout = Path.Combine(output, "streams", label + ".stdout"),
            stderr = Path.Combine(output, "streams", label + ".stderr"), audit = Path.Combine(output, "evidence", label + ".jsonl") };
        string[] arguments = [python, "-I", "-S", "-B", "-X", "pycache_prefix=" + prefix,
            bootstrap, child.audit, Path.Combine(output, "launch-config.json"), role, call.ToString()];
        var environment = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["SystemRoot"] = Text(config, "system_root"), ["PATH"] = Text(config, "runtime_path"),
            ["TEMP"] = Path.Combine(output, "temp"), ["TMP"] = Path.Combine(output, "temp"),
            ["TMPDIR"] = Path.Combine(output, "temp"), ["PYDANTIC_DISABLE_PLUGINS"] = "__all__"
        };
        string block = string.Join("\0", environment.Select(pair => pair.Key + "=" + pair.Value)) + "\0\0";
        IntPtr environmentBlock = Marshal.StringToHGlobalUni(block);
        IntPtr input = IntPtr.Zero, writer = IntPtr.Zero, standardOut = IntPtr.Zero, standardError = IntPtr.Zero;
        IntPtr attributes = IntPtr.Zero, handles = IntPtr.Zero;
        bool attributeInitialized = false, created = false, assigned = false, resumed = false;
        try
        {
            SecurityAttributes security = new() { length = Marshal.SizeOf<SecurityAttributes>(), inherit = 1 };
            Check(CreatePipe(out input, out writer, ref security, 0), "CreatePipe(stdin EOF)");
            Check(SetHandleInformation(writer, 1, 0), "disable writer inheritance");
            Check(CloseHandle(writer), "close stdin writer"); writer = IntPtr.Zero;
            standardOut = CreateFileW(Ordinary(child.stdout), WriteAccess, 1, ref security, CreateNew, Normal, IntPtr.Zero);
            Check(standardOut != Invalid, "CreateFileW stdout CREATE_NEW");
            standardError = CreateFileW(Ordinary(child.stderr), WriteAccess, 1, ref security, CreateNew, Normal, IntPtr.Zero);
            Check(standardError != Invalid, "CreateFileW stderr CREATE_NEW");
            UIntPtr bytes = UIntPtr.Zero;
            bool probe = InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref bytes);
            if (probe || bytes == UIntPtr.Zero || Marshal.GetLastWin32Error() != 122) throw new IOException("attribute sizing failed");
            attributes = Marshal.AllocHGlobal(checked((int)bytes.ToUInt64()));
            Check(InitializeProcThreadAttributeList(attributes, 1, 0, ref bytes), "InitializeProcThreadAttributeList");
            attributeInitialized = true;
            handles = Marshal.AllocHGlobal(IntPtr.Size * 3);
            Marshal.WriteIntPtr(handles, 0, input); Marshal.WriteIntPtr(handles, IntPtr.Size, standardOut);
            Marshal.WriteIntPtr(handles, IntPtr.Size * 2, standardError);
            Check(UpdateProcThreadAttribute(attributes, 0, HandleListAttribute, handles,
                (UIntPtr)(IntPtr.Size * 3), IntPtr.Zero, IntPtr.Zero), "restricted standard handle list");
            StartupInfoEx startup = new() { info = new StartupInfo { cb = Marshal.SizeOf<StartupInfoEx>(),
                flags = StartUseHandles, stdin = input, stdout = standardOut, stderr = standardError }, attributes = attributes };
            Record(new { kind = "launch-proposal", role, call, arguments, environment, cache_prefix_absent = prefix,
                inherited_handles = new[] { input.ToInt64(), standardOut.ToInt64(), standardError.ToInt64() },
                creation_flags = Suspended | UnicodeEnvironment | ExtendedStartup | NoWindow });
            Check(CreateProcessW(python, new StringBuilder(string.Join(" ", arguments.Select(Quote))), IntPtr.Zero,
                IntPtr.Zero, true, Suspended | UnicodeEnvironment | ExtendedStartup | NoWindow,
                environmentBlock, output, ref startup, out child.info), "CreateProcessW suspended");
            created = true;
            Check(AssignProcessToJobObject(job, child.info.process), "AssignProcessToJobObject (no resume fallback)");
            assigned = true;
            Record(new { kind = "owned-suspended", role, call, pid = child.info.pid, tid = child.info.tid,
                job_handle = job.ToInt64(), process_handle = child.info.process.ToInt64() });
            Check(ResumeThread(child.info.thread) == 1, "ResumeThread must observe exactly one suspend");
            resumed = true;
            return child;
        }
        catch
        {
            if (created && !assigned)
            {
                // Only our own still-suspended never-resumed process, outside the job.
                bool terminated = TerminateProcess(child.info.process, 125);
                uint wait = WaitForSingleObject(child.info.process, 5000);
                Record(new { kind = "assignment-refusal", pid = child.info.pid, resumed, terminated,
                    owned_suspended_termination = wait == WaitObject ? "STOPPED" : "UNKNOWN" });
            }
            if (created) child.Dispose();
            throw;
        }
        finally
        {
            if (attributeInitialized) DeleteProcThreadAttributeList(attributes);
            if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
            if (handles != IntPtr.Zero) Marshal.FreeHGlobal(handles);
            Marshal.FreeHGlobal(environmentBlock);
            foreach (IntPtr handle in new[] { input, writer, standardOut, standardError })
                if (handle != IntPtr.Zero && handle != Invalid) CloseHandle(handle);
        }
    }
    private static bool Ended(Child child)
    {
        uint value = WaitForSingleObject(child.info.process, 0);
        if (value != WaitObject && value != WaitTimeout) throw new InvalidOperationException("WaitForSingleObject Win32=" + Marshal.GetLastWin32Error());
        return value == WaitObject;
    }
    private static uint Exit(Child child)
    { Check(GetExitCodeProcess(child.info.process, out uint result), "GetExitCodeProcess"); return result; }
    private static bool CompleteAudit(string path)
    {
        if (!File.Exists(path)) return false;
        string? final = File.ReadLines(Ordinary(path)).LastOrDefault();
        if (final == null) return false;
        using JsonDocument row = JsonDocument.Parse(final);
        return Text(row.RootElement, "event") == "process-completed";
    }
    private static string Drain(IntPtr job, bool terminate)
    {
        if (terminate)
        {
            bool ok = TerminateJobObject(job, 124);
            Record(new { kind = "terminate-only-owned-job", job_handle = job.ToInt64(), ok,
                error = ok ? 0 : Marshal.GetLastWin32Error() });
        }
        Stopwatch timer = Stopwatch.StartNew();
        while (timer.ElapsedMilliseconds <= 5000)
        {
            bool ok = QueryInformationJobObject(job, 1, out Accounting value, (uint)Marshal.SizeOf<Accounting>(), IntPtr.Zero);
            Record(new { kind = "owned-job-accounting", ok, active = ok ? (uint?)value.activeProcesses : null });
            if (!ok) return "UNKNOWN";
            if (value.activeProcesses == 0) return "ACTIVE_COUNT_ZERO";
            Thread.Sleep(20);
        }
        return "UNKNOWN";
    }
    private static void Inventory(string path, List<object> rows)
    {
        Ordinary(path);
        foreach (string directory in Directory.GetDirectories(path).Order())
        { Ordinary(directory); rows.Add(new { path = directory, state = "DIRECTORY" }); Inventory(directory, rows); }
        foreach (string file in Directory.GetFiles(path).Order())
        { Ordinary(file); rows.Add(new { path = file, state = "FILE", bytes = new FileInfo(file).Length, sha256 = Hash(file) }); }
    }
    internal static int Main(string[] arguments)
    {
        // No build/runtime authority is embedded here. The immutable template refuses.
        if (arguments.Length != 1) return 78;
        using JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(Ordinary(arguments[0])));
        config = document.RootElement.Clone();
        if (!config.GetProperty("whole_journey_admitted").GetBoolean())
        { Console.Error.WriteLine("NOT_ADMITTED final-marker replacement/payload rollback; no process started"); return 78; }
        if (Text(config, "ast_recipe_status") != "OWNER_RECIPE_AND_VERSION_QUALIFIED")
        { Console.Error.WriteLine("NOT_ADMITTED original AST interpreter/schema equivalence pending; no process started"); return 78; }
        if (Text(config, "activation_status") != "EXACT_INDEPENDENT_REVIEW_AND_INT_ACTIVATION_REQUIRED") return 78;
        Pins();
        output = Ordinary(Text(config, "output"));
        if (File.Exists(output) || Directory.Exists(output)) throw new IOException("fresh absent output required");
        if (!Directory.Exists(Path.GetDirectoryName(output))) throw new IOException("ordinary existing parent required");
        Directory.CreateDirectory(output);
        foreach (string child in new[] { "control", "evidence", "evidence/preimages", "cases", "streams", "temp" })
            Directory.CreateDirectory(Path.Combine(output, child));
        log = new FileStream(Path.Combine(output, "supervisor.jsonl"), FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        WriteNew(Path.Combine(output, "launch-config.json"), config);
        IntPtr job = IntPtr.Zero;
        bool normal = false;
        string termination = "UNKNOWN";
        uint workerExit = 125;
        Watchdog? overallWatchdog = null;
        total = Stopwatch.StartNew();
        try
        {
            job = CreateJobObjectW(IntPtr.Zero, null); Check(job != IntPtr.Zero, "CreateJobObjectW unnamed owned job");
            ExtendedLimits limits = new() { basic = new BasicLimits { flags = 0x2000 } }; // KILL_ON_JOB_CLOSE; no breakaway
            Check(SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf<ExtendedLimits>()), "KILL_ON_JOB_CLOSE");
            overallWatchdog = new Watchdog(job, 180);
            using Child worker = Start(job, "worker", 0);
            int next = 1;
            while (!Ended(worker))
            {
                if (total.Elapsed.TotalSeconds > 180) throw new TimeoutException("total 180s");
                string ready = Path.Combine(output, "control", $"request-{next:00}.ready");
                if (File.Exists(ready))
                {
                    if (next > 25) throw new IOException("extra request");
                    using JsonDocument marker = JsonDocument.Parse(File.ReadAllBytes(Ordinary(ready)));
                    using JsonDocument request = JsonDocument.Parse(File.ReadAllBytes(Ordinary(
                        Path.Combine(output, "control", $"request-{next:00}.json"))));
                    JsonElement expected = config.GetProperty("calls")[next - 1];
                    if (marker.RootElement.GetProperty("id").GetInt32() != next ||
                        request.RootElement.GetProperty("id").GetInt32() != next ||
                        !request.RootElement.GetProperty("args").EnumerateArray().Select(x => x.GetString()).SequenceEqual(
                            expected.GetProperty("args").EnumerateArray().Select(x => x.GetString())))
                        throw new IOException("request differs from fixed command table");
                    using Watchdog cliWatchdog = new(job, 30);
                    using Child cli = Start(job, "cli", next);
                    Stopwatch clock = Stopwatch.StartNew();
                    while (!Ended(cli))
                    {
                        if (Ended(worker)) throw new IOException("worker died while owned CLI active");
                        if (total.Elapsed.TotalSeconds > 180 || clock.Elapsed.TotalSeconds > 30)
                            throw new TimeoutException("owned CLI 30s/total 180s");
                        Thread.Sleep(10);
                    }
                    uint code = Exit(cli); Pins();
                    if (Volatile.Read(ref watchdogFired) != 0) throw new TimeoutException("owned job watchdog fired");
                    bool complete = CompleteAudit(cli.audit);
                    Record(new { kind = "cli-exit", call = next, pid = cli.info.pid, native_exit = code,
                        audit_complete = complete, elapsed_seconds = clock.Elapsed.TotalSeconds });
                    if (!complete) throw new IOException("CLI guard/startup failure, not an oracle outcome");
                    WriteNew(Path.Combine(output, "control", $"response-{next:00}.json"), new
                    { id = next, exit = code, stdout = cli.stdout, stderr = cli.stderr, timed_out = false, receipt_complete = complete });
                    WriteNew(Path.Combine(output, "control", $"response-{next:00}.ready"), new { id = next });
                    next++;
                }
                Thread.Sleep(10);
            }
            workerExit = Exit(worker);
            if (workerExit != 0 || next != 26 || !CompleteAudit(worker.audit) || Volatile.Read(ref watchdogFired) != 0)
                throw new IOException("worker incomplete/failed/watchdog");
            Pins();
            termination = Drain(job, false);
            normal = termination == "ACTIVE_COUNT_ZERO";
            if (!normal) throw new IOException("descendant termination unknown");
        }
        catch (Exception error)
        {
            Record(new { kind = "supervisor-failed", error_type = error.GetType().Name, detail = error.Message });
            // The finally path also runs if writing this failure record itself fails.
        }
        finally
        {
            // Drain outstanding callbacks before any job handle can be closed/reused.
            overallWatchdog?.Dispose();
            try { if (job != IntPtr.Zero && !normal) termination = Drain(job, true); }
            finally { if (job != IntPtr.Zero) CloseHandle(job); }
            try
            {
                List<object> rows = new(); Inventory(output, rows);
                WriteNew(Path.Combine(output, "final-inventory.json"), rows);
                WriteNew(Path.Combine(output, "result.json"), new { worker_native_exit = workerExit,
                    termination, watchdog_fired = Volatile.Read(ref watchdogFired) != 0,
                    elapsed_seconds = total.Elapsed.TotalSeconds,
                    status = normal ? "COMPLETED_REQUIRES_INDEPENDENT_RESULT_REVIEW" : "FAILED_OR_UNKNOWN",
                    product_acceptance = false, hostname = "NOT_COLLECTED" });
            }
            finally { log?.Dispose(); }
        }
        return normal ? 0 : 125;
    }
}
