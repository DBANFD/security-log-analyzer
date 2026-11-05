# Creates a private in-process ETW session for this synthetic provider only.
# No existing sessions/channels are modified. No elevation is requested.
param([string]$OutputDirectory = 'work/windows-demo')
$ErrorActionPreference = 'Stop'
$folder = [IO.Path]::GetFullPath($OutputDirectory)
[IO.Directory]::CreateDirectory($folder) | Out-Null
$etl = Join-Path $folder 'synthetic.etl'
if (Test-Path -LiteralPath $etl) { throw 'Use a fresh output directory.' }
$session = 'SLA-Synthetic-' + [Guid]::NewGuid().ToString('N')
$provider = '{3f51f078-72f2-4d26-88e3-efdf9979a8a4}'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.ComponentModel;
public sealed class SLANativeWriter : IDisposable {
    [DllImport("advapi32.dll")] static extern uint EventRegister(ref Guid g, IntPtr cb, IntPtr context, out ulong handle);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] static extern uint EventWriteString(ulong handle, byte level, ulong keyword, string message);
    [DllImport("advapi32.dll")] static extern uint EventUnregister(ulong handle);
    ulong handle;
    public SLANativeWriter(Guid provider) {
        uint status=EventRegister(ref provider,IntPtr.Zero,IntPtr.Zero,out handle);
        if(status!=0) throw new Win32Exception((int)status);
    }
    public void Demo(string message,string ip) {
        uint status=EventWriteString(handle,4,0,message+" from "+ip);
        if(status!=0) throw new Win32Exception((int)status);
    }
    public void Dispose() { EventUnregister(handle); }
}
public sealed class SLAPrivateTrace : IDisposable {
    [StructLayout(LayoutKind.Sequential)] struct Wnode {
        public uint BufferSize, ProviderId;
        public ulong HistoricalContext;
        public long Timestamp;
        public Guid Guid;
        public uint ClientContext, Flags;
    }
    [StructLayout(LayoutKind.Sequential)] struct Properties {
        public Wnode Wnode;
        public uint BufferSize, MinimumBuffers, MaximumBuffers, MaximumFileSize, LogFileMode;
        public uint FlushTimer, EnableFlags, AgeLimit, NumberOfBuffers, FreeBuffers;
        public uint EventsLost, BuffersWritten, LogBuffersLost, RealTimeBuffersLost;
        public IntPtr LoggerThreadId;
        public uint LogFileNameOffset, LoggerNameOffset;
    }
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] static extern uint StartTraceW(out ulong h, string name, IntPtr p);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] static extern uint ControlTraceW(ulong h, string name, IntPtr p, uint code);
    [DllImport("advapi32.dll")] static extern uint EnableTraceEx2(ulong h, ref Guid guid, uint code, byte level, ulong any, ulong all, uint timeout, IntPtr parameters);
    IntPtr memory;
    ulong handle;
    string name;
    public SLAPrivateTrace(string name, string path, Guid provider) {
        this.name = name;
        int size = Marshal.SizeOf(typeof(Properties));
        int namesize = (name.Length + 1) * 2;
        int total = size + namesize + (path.Length + 1) * 2;
        memory = Marshal.AllocHGlobal(total);
        for(int i=0;i<total;i++) Marshal.WriteByte(memory,i,0);
        Properties p = new Properties();
        p.Wnode.BufferSize = (uint)total;
        p.Wnode.Guid = Guid.NewGuid();
        p.Wnode.ClientContext = 1;
        p.Wnode.Flags = 0x20000;
        p.BufferSize=64; p.MinimumBuffers=2; p.MaximumBuffers=4;
        p.LogFileMode=0x20801; // private logger + private in-process + sequential file
        p.LoggerNameOffset=(uint)size;
        p.LogFileNameOffset=(uint)(size+namesize);
        Marshal.StructureToPtr(p,memory,false);
        Marshal.Copy((name+"\0").ToCharArray(),0,IntPtr.Add(memory,size),name.Length+1);
        Marshal.Copy((path+"\0").ToCharArray(),0,IntPtr.Add(memory,size+namesize),path.Length+1);
        uint status=StartTraceW(out handle,name,memory);
        if(status!=0) { Marshal.FreeHGlobal(memory); memory=IntPtr.Zero; throw new Win32Exception((int)status); }
        status=EnableTraceEx2(handle,ref provider,1,5,ulong.MaxValue,0,0,IntPtr.Zero);
        if(status!=0) { Dispose(); throw new Win32Exception((int)status); }
    }
    public void Dispose() {
        if(memory==IntPtr.Zero) return;
        uint status=ControlTraceW(handle,name,memory,1);
        Marshal.FreeHGlobal(memory); memory=IntPtr.Zero;
        if(status!=0) throw new Win32Exception((int)status);
    }
}
'@
$source = New-Object SLANativeWriter([Guid]$provider)
$trace = $null
try {
    $trace = New-Object SLAPrivateTrace($session, $etl, [Guid]$provider)
    Start-Sleep -Milliseconds 250
    for ($i = 1; $i -le 6; $i++) { $source.Demo("demo-$i", '203.0.113.42') }
} finally {
    $source.Dispose()
    if ($null -ne $trace) { $trace.Dispose() }
}
& "$env:SystemRoot\System32\tracerpt.exe" $etl -o (Join-Path $folder 'synthetic.evtx') -of EVTX -lr -y
if ($LASTEXITCODE -ne 0) { throw 'Synthetic ETL generated, but EVTX conversion failed.' }
Write-Output "Synthetic ETL and EVTX saved under $folder. They can include Windows trace-header machine metadata; do not publish the binaries."
