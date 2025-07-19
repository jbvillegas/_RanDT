/*
    Master Rules File - RanDT Threat Detection System
    Author: Joaquin Villegas
    Description: Main YARA rules file that includes all detection categories and advanced threat patterns
    Date: 2025.07.15
    Version: 1.0
*/

// Include all rule categories
include "attachment.yar"
include "phishing.yar"
include "malware.yar"
include "documents.yar"
include "privacy.yar"
include "network.yar"

/*
    Advanced Persistent Threat (APT) Detection Rules
    These rules combine multiple indicators for sophisticated threat detection
*/

rule advanced_persistent_threat {
    meta:
        author = "Joaquin Villegas"
        description = "Detects APT-like behavior combining multiple threat indicators"
        category = "apt"
        severity = "critical"
        date = "2025.07.15"
        reference = "MITRE ATT&CK Framework"
    
    strings:
        // Persistence mechanisms
        $persist1 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $persist2 = "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $persist3 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $persist4 = "schtasks" nocase
        $persist5 = "at.exe" nocase
        
        // Network communication
        $network1 = "InternetOpenA" nocase
        $network2 = "HttpSendRequestA" nocase
        $network3 = "WinHttpOpen" nocase
        $network4 = "URLDownloadToFile" nocase
        $network5 = "socket" nocase
        
        // Stealth and evasion
        $stealth1 = "SetWindowsHookEx" nocase
        $stealth2 = "CreateMutex" nocase
        $stealth3 = "IsDebuggerPresent" nocase
        $stealth4 = "VirtualProtect" nocase
        $stealth5 = "WriteProcessMemory" nocase
        
        // Data collection and exfiltration
        $collect1 = "GetClipboardData" nocase
        $collect2 = "keylog" nocase
        $collect3 = "screenshot" nocase
        $collect4 = "enumerate" nocase
        
        // Cryptography (for secure communications)
        $crypto1 = "CryptEncrypt" nocase
        $crypto2 = "CryptDecrypt" nocase
        $crypto3 = "base64" nocase
        $crypto4 = "encrypt" nocase
        
    condition:
        (any of ($persist*)) and 
        (2 of ($network*)) and 
        (2 of ($stealth*)) and
        (any of ($collect*) or any of ($crypto*))
}

rule zero_day_exploit_attempt {
    meta:
        author = "Joaquin Villegas"
        description = "Detects potential zero-day exploit attempts and unknown attack patterns"
        category = "exploit"
        severity = "critical"
        date = "2025.07.15"
    
    strings:
        // Shellcode patterns
        $shellcode1 = { 90 90 90 90 }        // NOP sled
        $shellcode2 = { 31 C0 }              // XOR EAX, EAX
        $shellcode3 = { EB ?? }              // Short jump
        $shellcode4 = { E8 ?? ?? ?? ?? }     // Call instruction
        
        // Buffer overflow patterns
        $overflow1 = /A{100,}/               // Long string of A's
        $overflow2 = /\x41{50,}/             // Hex representation of A's
        $overflow3 = /%41{50,}/              // URL encoded A's
        
        // ROP gadgets
        $rop1 = { 58 C3 }                   // POP EAX; RET
        $rop2 = { 5D C3 }                   // POP EBP; RET
        $rop3 = { 59 C3 }                   // POP ECX; RET
        
        // Heap spray patterns
        $heap1 = { 0C 0C 0C 0C }            // Heap spray pattern
        $heap2 = /\x90{50,}/                // Long NOP sled
        
        // Exploit keywords
        $exploit1 = "exploit" nocase
        $exploit2 = "payload" nocase
        $exploit3 = "shellcode" nocase
        $exploit4 = "vulnerability" nocase
        
        // Format string bugs
        $format1 = /%n/
        $format2 = /%x/
        $format3 = /%.[\d]+x/
        
    condition:
        (any of ($shellcode*) and any of ($overflow*)) or
        (any of ($rop*) and any of ($heap*)) or
        (any of ($exploit*) and any of ($format*))
}

rule targeted_attack_indicators {
    meta:
        author = "Joaquin Villegas"
        description = "Detects indicators of targeted spear-phishing and social engineering attacks"
        category = "targeted"
        severity = "high"
        date = "2025.07.15"
    
    strings:
        // Targeting keywords
        $target1 = "confidential" nocase
        $target2 = "classified" nocase
        $target3 = "internal use only" nocase
        $target4 = "restricted" nocase
        $target5 = "proprietary" nocase
        
        // High-value targets
        $vip1 = "CEO" nocase
        $vip2 = "CFO" nocase
        $vip3 = "CTO" nocase
        $vip4 = "president" nocase
        $vip5 = "administrator" nocase
        $vip6 = "manager" nocase
        
        // Urgency indicators
        $urgency1 = "urgent" nocase
        $urgency2 = "immediate" nocase
        $urgency3 = "asap" nocase
        $urgency4 = "deadline" nocase
        $urgency5 = "time sensitive" nocase
        
        // Social engineering
        $social1 = "please review attached" nocase
        $social2 = "action required" nocase
        $social3 = "verify your account" nocase
        $social4 = "update your information" nocase
        $social5 = "click here to confirm" nocase
        
        // Suspicious attachments
        $attach1 = "Content-Disposition: attachment" nocase
        $attach2 = ".exe" nocase
        $attach3 = ".scr" nocase
        $attach4 = ".doc" nocase
        $attach5 = ".pdf" nocase
        
    condition:
        (any of ($target*) or any of ($vip*)) and 
        any of ($urgency*) and 
        (any of ($social*) or any of ($attach*))
}

rule multi_stage_malware {
    meta:
        author = "Joaquin Villegas"
        description = "Detects multi-stage malware deployment and infection chains"
        category = "malware"
        severity = "high"
        date = "2025.07.15"
    
    strings:
        // Stage indicators
        $stage1 = "dropper" nocase
        $stage2 = "loader" nocase
        $stage3 = "payload" nocase
        $stage4 = "installer" nocase
        $stage5 = "downloader" nocase
        
        // Download mechanisms
        $download1 = "DownloadFile" nocase
        $download2 = "URLDownloadToFile" nocase
        $download3 = "WinHttpReadData" nocase
        $download4 = "InternetReadFile" nocase
        $download5 = "curl" nocase
        $download6 = "wget" nocase
        
        // Execution methods
        $execute1 = "CreateProcess" nocase
        $execute2 = "ShellExecute" nocase
        $execute3 = "WinExec" nocase
        $execute4 = "system" nocase
        $execute5 = "exec" nocase
        
        // Temporary locations
        $temp1 = "%temp%" nocase
        $temp2 = "/tmp/" nocase
        $temp3 = "\\Windows\\Temp\\" nocase
        $temp4 = "AppData\\Local\\Temp\\" nocase
        
        // File operations
        $file1 = "WriteFile" nocase
        $file2 = "CreateFile" nocase
        $file3 = "DeleteFile" nocase
        $file4 = "MoveFile" nocase
        
    condition:
        any of ($stage*) and 
        any of ($download*) and 
        any of ($execute*) and 
        any of ($temp*) and 
        any of ($file*)
}

rule living_off_the_land {
    meta:
        author = "Joaquin Villegas"
        description = "Detects living-off-the-land techniques using legitimate tools maliciously"
        category = "lolbas"
        severity = "medium"
        date = "2025.07.15"
        reference = "LOLBAS Project"
    
    strings:
        // PowerShell abuse
        $ps1 = "powershell.exe" nocase
        $ps2 = "-EncodedCommand" nocase
        $ps3 = "-ExecutionPolicy Bypass" nocase
        $ps4 = "-WindowStyle Hidden" nocase
        $ps5 = "Invoke-Expression" nocase
        $ps6 = "DownloadString" nocase
        
        // CMD abuse
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "/c " nocase
        $cmd3 = "echo" nocase
        $cmd4 = "type" nocase
        
        // WMI abuse
        $wmi1 = "wmic" nocase
        $wmi2 = "Win32_Process" nocase
        $wmi3 = "Create" nocase
        
        // Registry abuse
        $reg1 = "reg.exe" nocase
        $reg2 = "regedit" nocase
        $reg3 = "add" nocase
        $reg4 = "query" nocase
        
        // Task scheduler
        $task1 = "schtasks" nocase
        $task2 = "/create" nocase
        $task3 = "/tn" nocase
        
        // Legitimate tools
        $tool1 = "certutil" nocase
        $tool2 = "bitsadmin" nocase
        $tool3 = "mshta" nocase
        $tool4 = "rundll32" nocase
        $tool5 = "regsvr32" nocase
        
    condition:
        (any of ($ps*) and ($ps2 or $ps3 or $ps4)) or
        (any of ($cmd*) and 2 of ($cmd*)) or
        (any of ($wmi*) and $wmi3) or
        (any of ($reg*) and ($reg3 or $reg4)) or
        (any of ($task*) and $task2) or
        any of ($tool*)
}

rule data_destruction_attack {
    meta:
        author = "Joaquin Villegas"
        description = "Detects destructive attacks aimed at data destruction or system disruption"
        category = "destruction"
        severity = "critical"
        date = "2025.07.15"
    
    strings:
        // Destruction commands
        $destroy1 = "del /f /s /q" nocase
        $destroy2 = "rmdir /s /q" nocase
        $destroy3 = "format" nocase
        $destroy4 = "fdisk" nocase
        $destroy5 = "rm -rf" nocase
        
        // System file targeting
        $system1 = "system32" nocase
        $system2 = "boot.ini" nocase
        $system3 = "ntldr" nocase
        $system4 = "mbr" nocase
        $system5 = "master boot record" nocase
        
        // Registry destruction
        $reg_destroy1 = "reg delete" nocase
        $reg_destroy2 = "HKEY_LOCAL_MACHINE\\SYSTEM" nocase
        $reg_destroy3 = "CurrentControlSet" nocase
        
        // Overwriting techniques
        $overwrite1 = "cipher /w" nocase
        $overwrite2 = "sdelete" nocase
        $overwrite3 = "shred" nocase
        $overwrite4 = "wipe" nocase
        
        // Malicious batch operations
        $batch1 = "for %%i in" nocase
        $batch2 = "do del" nocase
        $batch3 = "*.exe" nocase
        $batch4 = "*.dll" nocase
        
    condition:
        any of ($destroy*) and 
        (any of ($system*) or any of ($reg_destroy*)) or
        (any of ($overwrite*) and any of ($batch*))
}

rule supply_chain_attack {
    meta:
        author = "Joaquin Villegas"
        description = "Detects indicators of supply chain attacks and software tampering"
        category = "supply_chain"
        severity = "high"
        date = "2025.07.15"
    
    strings:
        // Software update mechanisms
        $update1 = "update.exe" nocase
        $update2 = "updater" nocase
        $update3 = "auto-update" nocase
        $update4 = "software update" nocase
        
        // Package managers
        $package1 = "npm install" nocase
        $package2 = "pip install" nocase
        $package3 = "apt-get install" nocase
        $package4 = "yum install" nocase
        
        // Code signing bypass
        $sign1 = "digital signature" nocase
        $sign2 = "certificate" nocase
        $sign3 = "unsigned" nocase
        $sign4 = "self-signed" nocase
        
        // Build processes
        $build1 = "makefile" nocase
        $build2 = "build.sh" nocase
        $build3 = "compile" nocase
        $build4 = "cmake" nocase
        
        // Suspicious modifications
        $modify1 = "patched" nocase
        $modify2 = "modified" nocase
        $modify3 = "injected" nocase
        $modify4 = "backdoor" nocase
        
    condition:
        (any of ($update*) or any of ($package*)) and
        any of ($sign*) and
        (any of ($build*) or any of ($modify*))
}

rule threat_hunting_indicators {
    meta:
        author = "Joaquin Villegas"
        description = "High-confidence indicators for proactive threat hunting"
        category = "hunting"
        severity = "medium"
        date = "2025.07.15"
    
    strings:
        // Unusual file locations
        $location1 = "\\Windows\\Temp\\" nocase
        $location2 = "\\Users\\Public\\" nocase
        $location3 = "\\ProgramData\\" nocase
        $location4 = "\\AppData\\Local\\Temp\\" nocase
        
        // Suspicious file names
        $name1 = "svchost.exe" nocase
        $name2 = "csrss.exe" nocase
        $name3 = "winlogon.exe" nocase
        $name4 = "lsass.exe" nocase
        
        // Anomalous network activity
        $network1 = "User-Agent: " nocase
        $network2 = "POST" nocase
        $network3 = "base64" nocase
        $network4 = "HTTP/1.1" nocase
        
        // Time-based indicators
        $time1 = "sleep" nocase
        $time2 = "delay" nocase
        $time3 = "interval" nocase
        $time4 = "timer" nocase
        
        // Encoding/Obfuscation
        $encode1 = "base64" nocase
        $encode2 = "hex" nocase
        $encode3 = "rot13" nocase
        $encode4 = "xor" nocase
        
    condition:
        any of ($location*) and 
        any of ($name*) and
        (any of ($network*) or any of ($time*) or any of ($encode*))
}

/*
    Meta-rule for comprehensive threat scoring
    This rule provides an overall threat assessment
*/

rule comprehensive_threat_assessment {
    meta:
        author = "Joaquin Villegas"
        description = "Comprehensive threat assessment combining multiple rule categories"
        category = "assessment"
        severity = "variable"
        date = "2025.07.15"
    
    condition:
        // Count matches across different rule categories
        (
            // Email threats
            (with_attachment or without_attachment or phising) or
            
            // Document threats  
            (macro_enabled_document or pdf_with_javascript or rtf_exploit_document) or
            
            // Malware indicators
            (suspicious_executable or ransomware_indicators or trojan_behavior) or
            
            // Privacy violations
            (credential_harvesting or browser_data_theft or crypto_wallet_theft) or
            
            // Network threats
            (command_and_control_communication or dns_tunneling_detection or suspicious_network_traffic) or
            
            // Advanced threats
            (advanced_persistent_threat or zero_day_exploit_attempt or multi_stage_malware)
        )
}