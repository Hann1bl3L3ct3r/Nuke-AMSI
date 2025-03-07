
![banner](https://s11.gifyu.com/images/SysSH.gif)<br>
The AMSI Nuke Script is a PowerShell-based utility designed to modify the Anti-Malware Scan Interface (AMSI) in running PowerShell processes. This script exploits Windows API functions to alter the memory of the amsi.dll, effectively disabling its malware scanning capabilities. It serves as an educational tool for security researchers and penetration testers to understand AMSI's role in malware defense and the implications of circumventing such mechanisms.

### Concepts utilized
- Anti-Malware Scan Interface (AMSI) : The Windows Antimalware Scan Interface (AMSI) is a pivotal component in Microsoft’s security architecture, designed to enhance the detection of malicious scripts and behaviors by providing applications and services with a standardized interface to request content scans. As cyber threats evolve, so do the techniques employed by attackers to evade such defenses.
- Windows API Functions:
Utilized to manipulate process memory and load dynamic link libraries (NTDll.dll & Kernel32.dll).
Functions include NtOpenProcess, NtWriteVirtualMemory, VirtualProtectEx, and others.

### Key Features
- *Direct Memory Manipulation*: NukeAMSI utilizes direct memory manipulation techniques to disable AMSI, leveraging the ntdll library and other critical Windows APIs. This ensures that AMSI is effectively bypassed without raising alerts or triggering additional security measures.
  
- *Stealth Operations*: The tool operates in-memory, meaning it leaves no trace on disk. This makes it particularly useful in scenarios where maintaining operational security is paramount.
 

### Technical Breakdown

NukeAMSI uses several advanced techniques to achieve its goals:

- *Process Injection*: By injecting code into the memory space of the PowerShell process, NukeAMSI can alter the behavior of critical security functions.
  
- *Utilization of NTDLL*: The script makes use of ntdll, a core Windows library, to access low-level system functions. This allows NukeAMSI to manipulate the system's memory directly, making its operations more effective and harder to detect.
  
- *Advanced Error Handling*: NukeAMSI includes robust error handling to ensure smooth operation even in complex environments. It carefully checks for and handles potential failures, reducing the likelihood of detection or script failure.

### Modifications

This version of NukeAMSI has been modified in the following ways: 

- Execute immediately on call
- Output has been formatted for easier reading with [+] for positive output and [-] for errors
- NtWriteVirtualMemory is now called indirectly to improve stealth and minimize risk of detection (NtWriteVirtualMemory is a common call for loaders and is often flagged)

### Conclusion

NukeAMSI represents the cutting edge of AMSI bypass techniques, offering a powerful, reliable, and stealthy solution for professionals who need to execute scripts in environments where AMSI is active. Whether you're conducting penetration testing, research, or learning more about Windows security internals, NukeAMSI provides the tools you need to operate effectively and securely.
<br><br>

> Note: This tool is intended for **educational purposes only*. It should be used responsibly and in compliance with all relevant laws and regulations. Unauthorized use of this tool on systems you do not own or have explicit permission to test can result in severe legal consequences.


