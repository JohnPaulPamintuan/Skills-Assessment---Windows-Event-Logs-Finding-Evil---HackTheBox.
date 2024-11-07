# Skills Assessment - Windows Event Logs & Finding Evil - HackTheBox.
This module covers the exploration of Windows Event Logs and their significance in uncovering suspicious activities. Throughout the course, we delve into the anatomy of Windows Event Logs and highlight the logs that hold the most valuable information for investigations. The module also focuses on utilizing Sysmon and Event Logs for detecting and analyzing malicious behavior. Additionally, we delve into Event Tracing for Windows (ETW), explaining its architecture and components, and provide ETW-based detection examples. To streamline the analysis process, we introduce the powerful Get-WinEvent cmdlet.

[Link to the Module](https://academy.hackthebox.com/module/details/216)

1. By examining the logs located in the “C:\Logs\DLLHijack” directory, determine the process responsible for executing a DLL hijacking attack. Enter the process name as your answer. Answer format: _.exe
   - Using Get-WinEvent, I attempted to filter for events related to DLL hijacking attacks. While this might not be the most efficient method, I recalled that DLLs involved in such attacks are often unsigned. Therefore, I searched for events with ID 7 AND those with the message “signed: false
   - I run: Get-WinEvent -Path 'C:\Logs\DLLHijack\*' | Where-Object{$_.ID -like "7"} | Where-Object{$_.Message -like "*signed: false*"} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message

2. By examining the logs located in the “C:\Logs\PowershellExec” directory, determine the process that executed unmanaged PowerShell code. Enter the process name as your answer. Answer format: _.exe
   - As per the guide, the presence of “Microsoft .NET Runtime…”, clr.dll, and clrjit.dll in processes that typically don’t require them is indicative of potential execute-assembly or unmanaged PowerShell injection attacks. These DLLs are typically used for executing C# code. Therefore, I searched for events containing “clr.dll”. The initial results highlighted a suspicious executable file that should not have access to this DLL.
   - I run: Get-WinEvent -Path 'C:\Logs\PowershellExec\*' | Where-Object{$_.ID -like "7"} | Where-Object{$_.Message -like "*clr.dll*"} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message

3. By examining the logs located in the “C:\Logs\PowershellExec” directory, determine the process that injected into the process that executed unmanaged PowerShell code. Enter the process name as your answer. Answer format: _.exe
   - For this specific scenario, I focused on Calculator.exe and filtered events with ID 8, indicating a CreateRemoteThread operation.
   - I run: Get-WinEvent -Path 'C:\Logs\PowershellExec\*' | Where-Object{$_.ID -like "8"} | Where-Object{$_.Message -like "*Calculator.exe*"} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message

4. By examining the logs located in the “C:\Logs\Dump” directory, determine the process that performed an LSASS dump. Enter the process name as your answer. Answer format: _.exe
   - I filtered for events with ID 10 (ProcessAccess) and searched for entries targeting lsass.exe. While there were multiple results, only one was initiated by a suspicious executable file.
   - I run: Get-WinEvent -Path 'C:\Logs\Dump\*' | Where-Object{$_.ID -like "10"} | Where-Object{$_.Message -like "*TargetImage*lsass.exe*"} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message
  
5. By examining the logs located in the “C:\Logs\StrangePPID” directory, determine a process that was used to temporarily execute code based on a strange parent-child relationship. Enter the process name as your answer. Answer format: _.exe
   - Finally, I filtered for events with ID 1 (Process creation). There were limited results, and only one of them appeared suspicious.
   - i run: Get-WinEvent -Path 'C:\Logs\StrangePPID\*' | Where-Object{$_.ID -like "1"} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message
