/*
    Suspicious Document Detection Rules
    Author: Joaquin Villegas
    Description: Comprehensive YARA rules to detect malicious and suspicious documents
    Date: 2025.07.15
*/

rule macro_enabled_document {
    meta:
        author = "Joaquin Villegas"
        description = "Detects macro-enabled Office documents with suspicious content"
        category = "document"
        severity = "high"
        date = "2025.07.15"
    
    strings:
        // OLE file header (Office documents)
        $ole_header = { D0 CF 11 E0 A1 B1 1A E1 }
        
        // Macro indicators
        $macro1 = "macros" nocase
        $macro2 = "VBA" nocase
        $macro3 = "AutoOpen" nocase
        $macro4 = "Auto_Open" nocase
        $macro5 = "Document_Open" nocase
        $macro6 = "Workbook_Open" nocase
        $macro7 = "Auto_Close" nocase
        $macro8 = "Document_Close" nocase
        
        // Suspicious VBA functions
        $vba_sus1 = "Shell" nocase
        $vba_sus2 = "CreateObject" nocase
        $vba_sus3 = "WScript.Shell" nocase
        $vba_sus4 = "WinExec" nocase
        $vba_sus5 = "URLDownloadToFile" nocase
        $vba_sus6 = "InternetOpen" nocase
        $vba_sus7 = "GetObject" nocase
        $vba_sus8 = "CallByName" nocase
        
        // PowerShell execution
        $powershell1 = "powershell" nocase
        $powershell2 = "pwsh" nocase
        $powershell3 = "cmd.exe" nocase
        $powershell4 = "/c " nocase
        
        // Obfuscation indicators
        $obfusc1 = "Chr(" nocase
        $obfusc2 = "Asc(" nocase
        $obfusc3 = "StrReverse" nocase
        $obfusc4 = "Replace(" nocase
        $obfusc5 = "Split(" nocase
        
    condition:
        $ole_header at 0 and 
        (any of ($macro*) or any of ($vba_sus*)) and
        (any of ($powershell*) or 2 of ($obfusc*))
}

rule pdf_with_javascript {
    meta:
        author = "Joaquin Villegas"
        description = "Detects PDF files with embedded JavaScript and suspicious content"
        category = "document"
        severity = "medium"
        date = "2025.07.15"
    
    strings:
        // PDF header
        $pdf_header = "%PDF-"
        
        // JavaScript indicators
        $js1 = "/JavaScript" nocase
        $js2 = "/JS" nocase
        $js3 = "/OpenAction" nocase
        $js4 = "/AA" nocase
        
        // Suspicious JavaScript functions
        $js_func1 = "app.alert" nocase
        $js_func2 = "this.print" nocase
        $js_func3 = "app.launchURL" nocase
        $js_func4 = "this.submitForm" nocase
        $js_func5 = "app.response" nocase
        $js_func6 = "this.importDataObject" nocase
        
        // Exploit indicators
        $exploit1 = "unescape" nocase
        $exploit2 = "eval" nocase
        $exploit3 = "String.fromCharCode" nocase
        $exploit4 = "document.write" nocase
        
        // Heap spray indicators
        $heap1 = /\x90{10,}/  // NOP sled
        $heap2 = /%u9090/     // Unicode NOP
        $heap3 = /\x0c\x0c\x0c\x0c/  // Heap spray pattern
        
        // Form actions
        $form1 = "/F " nocase
        $form2 = "/Type/Action" nocase
        $form3 = "/S/SubmitForm" nocase
        
    condition:
        $pdf_header at 0 and 
        (any of ($js*) or any of ($js_func*)) and
        (any of ($exploit*) or any of ($heap*) or any of ($form*))
}

rule rtf_exploit_document {
    meta:
        author = "Joaquin Villegas"
        description = "Detects RTF files with potential exploits and malicious content"
        category = "document"
        severity = "high"
        date = "2025.07.15"
    
    strings:
        // RTF header
        $rtf_header = "{\\rtf"
        
        // Object embedding
        $object1 = "\\object" nocase
        $object2 = "\\objdata" nocase
        $object3 = "\\objclass" nocase
        $object4 = "\\objw" nocase
        $object5 = "\\objh" nocase
        
        // Embedded objects
        $embed1 = "\\objemb" nocase
        $embed2 = "\\objlink" nocase
        $embed3 = "\\objautlink" nocase
        
        // Equation Editor exploits
        $equation1 = "Equation.3" nocase
        $equation2 = "Microsoft Equation" nocase
        
        // Shellcode patterns
        $shellcode1 = { 90 90 90 90 }  // NOP sled
        $shellcode2 = { 31 C0 }        // XOR EAX, EAX
        $shellcode3 = { EB ?? }        // Short jump
        
        // CVE-specific patterns
        $cve_2017_11882 = "0002CE020000"
        $cve_2018_0802 = "EQNEDT32.EXE"
        
        // Suspicious hex data
        $hex_pattern1 = /\\[0-9a-fA-F]{100,}/
        $hex_pattern2 = /[0-9a-fA-F]{200,}/
        
    condition:
        $rtf_header at 0 and 
        (any of ($object*) or any of ($embed*)) and
        (any of ($equation*) or any of ($shellcode*) or any of ($cve_*) or any of ($hex_pattern*))
}

rule suspicious_zip_archive {
    meta:
        author = "Joaquin Villegas"
        description = "Detects suspicious ZIP archives with malicious content"
        category = "document"
        severity = "medium"
        date = "2025.07.15"
    
    strings:
        // ZIP headers
        $zip_header = { 50 4B 03 04 }   // Local file header
        $zip_central = { 50 4B 01 02 }  // Central directory header
        
        // Dangerous file extensions in archive
        $exe_in_zip = ".exe" nocase
        $scr_in_zip = ".scr" nocase
        $bat_in_zip = ".bat" nocase
        $cmd_in_zip = ".cmd" nocase
        $vbs_in_zip = ".vbs" nocase
        $js_in_zip = ".js" nocase
        $jar_in_zip = ".jar" nocase
        $com_in_zip = ".com" nocase
        $pif_in_zip = ".pif" nocase
        
        // Double extensions (social engineering)
        $double_ext1 = ".pdf.exe" nocase
        $double_ext2 = ".doc.exe" nocase
        $double_ext3 = ".jpg.exe" nocase
        $double_ext4 = ".txt.scr" nocase
        $double_ext5 = ".invoice.exe" nocase
        
        // Password protection indicators
        $password1 = "password" nocase
        $password2 = "encrypted" nocase
        $password3 = "protected" nocase
        
        // Suspicious filenames
        $suspicious_name1 = "invoice" nocase
        $suspicious_name2 = "receipt" nocase
        $suspicious_name3 = "document" nocase
        $suspicious_name4 = "payment" nocase
        $suspicious_name5 = "order" nocase
        
    condition:
        $zip_header at 0 and 
        (any of ($*_in_zip) or any of ($double_ext*)) and
        (any of ($password*) or any of ($suspicious_name*))
}

rule office_template_injection {
    meta:
        author = "Joaquin Villegas"
        description = "Detects Office template injection attacks"
        category = "document"
        severity = "high"
        date = "2025.07.15"
    
    strings:
        // OLE header
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        
        // Template references
        $template1 = "Template" nocase
        $template2 = "attachedTemplate" nocase
        $template3 = "documentTemplate" nocase
        $template4 = "globalTemplate" nocase
        
        // Remote locations
        $remote1 = "http://" nocase
        $remote2 = "https://" nocase
        $remote3 = "ftp://" nocase
        $remote4 = "\\\\[0-9]" // UNC path with IP
        
        // Template file extensions
        $dotm = ".dotm" nocase
        $dotx = ".dotx" nocase
        $potm = ".potm" nocase
        $xltm = ".xltm" nocase
        
        // Relationships
        $rel1 = "relationships" nocase
        $rel2 = "Target=" nocase
        $rel3 = "TargetMode=" nocase
        
    condition:
        $ole at 0 and 
        any of ($template*) and 
        (any of ($remote*) or any of ($dotm, $dotx, $potm, $xltm)) and
        any of ($rel*)
}

rule suspicious_powershell_in_doc {
    meta:
        author = "Joaquin Villegas"
        description = "Detects PowerShell execution attempts in documents"
        category = "document"
        severity = "high"
        date = "2025.07.15"
    
    strings:
        // PowerShell indicators
        $ps1 = "powershell" nocase
        $ps2 = "pwsh" nocase
        $ps3 = "powershell.exe" nocase
        
        // PowerShell parameters
        $param1 = "-EncodedCommand" nocase
        $param2 = "-enc" nocase
        $param3 = "-ExecutionPolicy" nocase
        $param4 = "-ep" nocase
        $param5 = "-WindowStyle" nocase
        $param6 = "-w" nocase
        $param7 = "-NoProfile" nocase
        $param8 = "-nop" nocase
        
        // Bypass techniques
        $bypass1 = "Bypass" nocase
        $bypass2 = "Unrestricted" nocase
        $bypass3 = "Hidden" nocase
        $bypass4 = "Minimized" nocase
        
        // Download functions
        $download1 = "DownloadString" nocase
        $download2 = "DownloadFile" nocase
        $download3 = "WebClient" nocase
        $download4 = "Invoke-WebRequest" nocase
        $download5 = "iwr" nocase
        $download6 = "curl" nocase
        $download7 = "wget" nocase
        
        // Execution functions
        $exec1 = "Invoke-Expression" nocase
        $exec2 = "iex" nocase
        $exec3 = "Invoke-Command" nocase
        $exec4 = "Start-Process" nocase
        
        // Base64 encoded content
        $base64_pattern = /[A-Za-z0-9+\/]{50,}={0,2}/
        
    condition:
        any of ($ps*) and 
        (any of ($param*) or any of ($bypass*)) and
        (any of ($download*) or any of ($exec*) or $base64_pattern)
}

rule malicious_script_in_document {
    meta:
        author = "Joaquin Villegas"
        description = "Detects malicious scripts embedded in documents"
        category = "document"
        severity = "medium"
        date = "2025.07.15"
    
    strings:
        // Script language indicators
        $script1 = "<script" nocase
        $script2 = "javascript:" nocase
        $script3 = "vbscript:" nocase
        $script4 = "ActiveXObject" nocase
        
        // Dangerous functions
        $danger1 = "eval(" nocase
        $danger2 = "unescape(" nocase
        $danger3 = "fromCharCode(" nocase
        $danger4 = "createElement(" nocase
        $danger5 = "appendChild(" nocase
        
        // File system access
        $file1 = "FileSystemObject" nocase
        $file2 = "Scripting.FileSystemObject" nocase
        $file3 = "WScript.Shell" nocase
        $file4 = "Shell.Application" nocase
        
        // Network access
        $net1 = "XMLHttpRequest" nocase
        $net2 = "WinHttp.WinHttpRequest" nocase
        $net3 = "Microsoft.XMLHTTP" nocase
        
        // Process execution
        $proc1 = "WScript.Shell.Run" nocase
        $proc2 = "WScript.Shell.Exec" nocase
        $proc3 = "CreateObject" nocase
        
    condition:
        any of ($script*) and 
        (any of ($danger*) or any of ($file*) or any of ($net*) or any of ($proc*))
}

rule document_with_embedded_executable {
    meta:
        author = "Joaquin Villegas"
        description = "Detects documents with embedded executable content"
        category = "document"
        severity = "critical"
        date = "2025.07.15"
    
    strings:
        // Document headers
        $pdf_header = "%PDF-"
        $ole_header = { D0 CF 11 E0 A1 B1 1A E1 }
        $rtf_header = "{\\rtf"
        
        // Executable headers within document
        $pe_header = { 4D 5A }      // MZ header
        $elf_header = { 7F 45 4C 46 } // ELF header
        $macho_header = { FE ED FA CE } // Mach-O header
        
        // Embedded object indicators
        $embed1 = "\\objemb" nocase
        $embed2 = "/EmbeddedFile" nocase
        $embed3 = "Package" nocase
        $embed4 = "OLE Object" nocase
        
        // File streams
        $stream1 = "\\objdata" nocase
        $stream2 = "/F " nocase
        $stream3 = "/Type/EmbeddedFile" nocase
        
    condition:
        (any of ($*_header) at 0) and 
        (any of ($pe_header, $elf_header, $macho_header)) and
        (any of ($embed*) or any of ($stream*))
}

rule suspicious_document_metadata {
    meta:
        author = "Joaquin Villegas"
        description = "Detects suspicious metadata in documents"
        category = "document"
        severity = "low"
        date = "2025.07.15"
    
    strings:
        // Suspicious author names
        $author1 = "Admin" nocase
        $author2 = "Administrator" nocase
        $author3 = "User" nocase
        $author4 = "test" nocase
        $author5 = "user1" nocase
        
        // Suspicious creation tools
        $tool1 = "msfvenom" nocase
        $tool2 = "metasploit" nocase
        $tool3 = "cobalt strike" nocase
        $tool4 = "empire" nocase
        $tool5 = "powersploit" nocase
        
        // Metadata fields
        $meta1 = "/Author" nocase
        $meta2 = "/Creator" nocase
        $meta3 = "/Producer" nocase
        $meta4 = "/Subject" nocase
        $meta5 = "/Title" nocase
        
        // Template origins
        $template1 = "normal.dotm" nocase
        $template2 = "blank.dotx" nocase
        $template3 = "template" nocase
        
        // Suspicious subjects/titles
        $subject1 = "invoice" nocase
        $subject2 = "receipt" nocase
        $subject3 = "payment" nocase
        $subject4 = "urgent" nocase
        $subject5 = "confidential" nocase
        
    condition:
        any of ($meta*) and 
        (any of ($author*) or any of ($tool*) or any of ($template*) or 2 of ($subject*))
}

rule document_with_external_references {
    meta:
        author = "Joaquin Villegas"
        description = "Detects documents with suspicious external references"
        category = "document"
        severity = "medium"
        date = "2025.07.15"
    
    strings:
        // External references
        $ext_ref1 = "http://" nocase
        $ext_ref2 = "https://" nocase
        $ext_ref3 = "ftp://" nocase
        $ext_ref4 = "file://" nocase
        
        // UNC paths
        $unc1 = /\\\\[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/
        $unc2 = /\\\\[a-zA-Z0-9.-]+\\/
        
        // Reference types
        $ref_type1 = "/URI" nocase
        $ref_type2 = "/Type/Action" nocase
        $ref_type3 = "/S/URI" nocase
        $ref_type4 = "Target=" nocase
        $ref_type5 = "hyperlink" nocase
        
        // Suspicious domains
        $suspicious_tld1 = ".tk/" nocase
        $suspicious_tld2 = ".ml/" nocase
        $suspicious_tld3 = ".ga/" nocase
        $suspicious_tld4 = ".cf/" nocase
        
        // IP addresses
        $ip_pattern = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/
        
    condition:
        (any of ($ext_ref*) or any of ($unc*)) and 
        any of ($ref_type*) and
        (any of ($suspicious_tld*) or $ip_pattern)
}