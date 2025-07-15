/*
    Network and Communication Threats Detection Rules
    Author: Joaquin Villegas
    Description: Comprehensive YARA rules to detect network-based threats and suspicious communications
    Date: 2025.07.15
*/

rule command_and_control_communication {
    meta:
        author = "Joaquin Villegas"
        description = "Detects command and control communications"
        category = "network"
        severity = "high"
        date = "2025.07.15"
    
    strings:
        // C2 indicators
        $c2_1 = "beacon" nocase
        $c2_2 = "heartbeat" nocase
        $c2_3 = "checkin" nocase
        $c2_4 = "c2" nocase
        $c2_5 = "botnet" nocase
        $c2_6 = "bot_id" nocase
        $c2_7 = "command_id" nocase
        $c2_8 = "control" nocase
        
        // Network protocols
        $protocol1 = "http://" nocase
        $protocol2 = "https://" nocase
        $protocol3 = "tcp://" nocase
        $protocol4 = "udp://" nocase
        $protocol5 = "ftp://" nocase
        
        // Encoding indicators
        $base64_pattern = /[A-Za-z0-9+\/]{40,}={0,2}/
        $hex_pattern = /[0-9a-fA-F]{20,}/
        $encrypted = "encrypted" nocase
        $encoded = "encoded" nocase
        
        // Communication patterns
        $interval1 = "interval" nocase
        $sleep1 = "sleep" nocase
        $delay1 = "delay" nocase
        $timeout1 = "timeout" nocase
        
        // Bot commands
        $cmd1 = "download" nocase
        $cmd2 = "execute" nocase
        $cmd3 = "upload" nocase
        $cmd4 = "screenshot" nocase
        $cmd5 = "keylog" nocase
        
    condition:
        (2 of ($c2_*)) and 
        any of ($protocol*) and 
        (any of ($base64_pattern, $hex_pattern, $encrypted, $encoded)) and
        (any of ($interval*, $sleep*, $delay*, $timeout*) or any of ($cmd*))
}

rule dns_tunneling_detection {
    meta:
        author = "Joaquin Villegas"
        description = "Detects DNS tunneling attempts for data exfiltration"
        category = "network"
        severity = "high"
        date = "2025.07.15"
    
    strings:
        // DNS tools and commands
        $dns1 = "nslookup" nocase
        $dns2 = "dig" nocase
        $dns3 = "host" nocase
        $dns4 = "resolve" nocase
        $dns5 = "query" nocase
        
        // Tunneling indicators
        $tunnel1 = "tunnel" nocase
        $tunnel2 = "exfiltrate" nocase
        $tunnel3 = "covert" nocase
        $tunnel4 = "steganography" nocase
        
        // DNS record types used for tunneling
        $record1 = "TXT" nocase
        $record2 = "CNAME" nocase
        $record3 = "MX" nocase
        $record4 = "NULL" nocase
        
        // Long subdomains (common in DNS tunneling)
        $long_subdomain = /[a-zA-Z0-9]{50,}\./
        $encoded_subdomain = /[A-Za-z0-9+\/]{30,}\./
        
        // Base64-like data in DNS queries
        $base64_dns = /[A-Za-z0-9+\/]{20,}\..*\./
        
        // Suspicious domain patterns
        $random_domain = /[a-z0-9]{10,20}\.(com|net|org|info)/i
        
    condition:
        (any of ($dns*) and any of ($tunnel*)) or
        (any of ($record*) and ($long_subdomain or $encoded_subdomain)) or
        ($base64_dns and $random_domain)
}

rule suspicious_network_traffic {
    meta:
        author = "Joaquin Villegas"
        description = "Detects suspicious network traffic patterns and anonymization tools"
        category = "network"
        severity = "medium"
        date = "2025.07.15"
    
    strings:
        // Tor indicators
        $tor1 = "tor" nocase
        $tor2 = ".onion" nocase
        $tor3 = "torrc" nocase
        $tor4 = "tor browser" nocase
        $tor5 = "onion routing" nocase
        
        // Proxy indicators
        $proxy1 = "proxy" nocase
        $proxy2 = "socks" nocase
        $proxy3 = "http_proxy" nocase
        $proxy4 = "https_proxy" nocase
        $proxy5 = "proxy_host" nocase
        
        // VPN indicators
        $vpn1 = "vpn" nocase
        $vpn2 = "openvpn" nocase
        $vpn3 = "wireguard" nocase
        $vpn4 = "ipsec" nocase
        
        // Anonymization tools
        $anon1 = "anonymous" nocase
        $anon2 = "anonymize" nocase
        $anon3 = "hide ip" nocase
        $anon4 = "mask ip" nocase
        
        // Suspicious ports
        $port1 = ":4444"    // Common backdoor port
        $port2 = ":8080"    // Common proxy port
        $port3 = ":9050"    // Tor SOCKS port
        $port4 = ":1080"    // SOCKS proxy port
        $port5 = ":3128"    // Squid proxy port
        $port6 = ":8888"    // Alternative proxy port
        
        // Traffic obfuscation
        $obfusc1 = "obfuscate" nocase
        $obfusc2 = "steganography" nocase
        $obfusc3 = "covert channel" nocase
        
    condition:
        (any of ($tor*) or (any of ($proxy*) and any of ($anon*))) or
        (2 of ($port*)) or
        (any of ($vpn*) and any of ($obfusc*))
}

rule data_exfiltration_protocols {
    meta:
        author = "Joaquin Villegas"
        description = "Detects data exfiltration attempts via various protocols"
        category = "network"
        severity = "high"
        date = "2025.07.15"
    
    strings:
        // File transfer protocols
        $ftp1 = "ftp://" nocase
        $ftp2 = "sftp://" nocase
        $ftp3 = "ftps://" nocase
        $ftp4 = "ftp.upload" nocase
        
        // HTTP methods for data transfer
        $http1 = "POST" nocase
        $http2 = "PUT" nocase
        $http3 = "PATCH" nocase
        $http4 = "multipart/form-data" nocase
        
        // Email protocols
        $email1 = "smtp://" nocase
        $email2 = "sendmail" nocase
        $email3 = "mail.send" nocase
        $email4 = "email.attach" nocase
        
        // Cloud storage services
        $cloud1 = "dropbox.com" nocase
        $cloud2 = "drive.google.com" nocase
        $cloud3 = "onedrive.live.com" nocase
        $cloud4 = "box.com" nocase
        $cloud5 = "mega.nz" nocase
        $cloud6 = "mediafire.com" nocase
        $cloud7 = "wetransfer.com" nocase
        $cloud8 = "sendspace.com" nocase
        
        // Exfiltration indicators
        $exfil1 = "upload" nocase
        $exfil2 = "exfiltrate" nocase
        $exfil3 = "leak" nocase
        $exfil4 = "dump" nocase
        $exfil5 = "backup" nocase
        $exfil6 = "sync" nocase
        
        // Data compression (often used before exfiltration)
        $compress1 = "compress" nocase
        $compress2 = "zip" nocase
        $compress3 = "rar" nocase
        $compress4 = "tar" nocase
        $compress5 = "gzip" nocase
        
        // Large data patterns
        $large_data = /Content-Length:\s*[1-9][0-9]{6,}/i  // > 1MB
        
    condition:
        (any of ($ftp*) or any of ($http*) or any of ($email*) or any of ($cloud*)) and
        (any of ($exfil*) or any of ($compress*) or $large_data)
}

rule malicious_domains_and_urls {
    meta:
        author = "Joaquin Villegas"
        description = "Detects connections to suspicious and malicious domains"
        category = "network"
        severity = "medium"
        date = "2025.07.15"
    
    strings:
        // Suspicious free TLDs often used by malware
        $suspicious_tld1 = ".tk" nocase
        $suspicious_tld2 = ".ml" nocase
        $suspicious_tld3 = ".ga" nocase
        $suspicious_tld4 = ".cf" nocase
        $suspicious_tld5 = ".pw" nocase
        $suspicious_tld6 = ".cc" nocase
        
        // Domain generation algorithm patterns
        $dga_pattern1 = /[a-z]{8,15}\.(com|net|org|info|biz)/i
        $dga_pattern2 = /[a-z0-9]{10,20}\.(tk|ml|ga|cf)/i
        
        // Suspicious domain characteristics
        $random_subdomain = /[a-z0-9]{8,}-[a-z0-9]{8,}\./i
        $numbered_domain = /[a-z]+[0-9]{3,}\./i
        
        // URL shorteners (potential for malicious redirects)
        $shortener1 = "bit.ly" nocase
        $shortener2 = "tinyurl.com" nocase
        $shortener3 = "t.co" nocase
        $shortener4 = "goo.gl" nocase
        $shortener5 = "ow.ly" nocase
        $shortener6 = "short.link" nocase
        
        // Suspicious URL patterns
        $suspicious_path1 = "/admin" nocase
        $suspicious_path2 = "/panel" nocase
        $suspicious_path3 = "/gate" nocase
        $suspicious_path4 = "/bot" nocase
        $suspicious_path5 = "/api/v1/bot" nocase
        
        // IP-based URLs (often suspicious)
        $ip_url = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/
        
        // Dynamic DNS services
        $dyndns1 = "dyndns.org" nocase
        $dyndns2 = "no-ip.com" nocase
        $dyndns3 = "ddns.net" nocase
        
    condition:
        (any of ($suspicious_tld*) or any of ($dga_pattern*) or any of ($random_subdomain, $numbered_domain)) or
        (any of ($shortener*) and any of ($suspicious_path*)) or
        ($ip_url or any of ($dyndns*))
}

rule irc_botnet_communication {
    meta:
        author = "Joaquin Villegas"
        description = "Detects IRC botnet communications and commands"
        category = "network"
        severity = "high"
        date = "2025.07.15"
    
    strings:
        // IRC protocol commands
        $irc1 = "NICK " nocase
        $irc2 = "USER " nocase
        $irc3 = "JOIN " nocase
        $irc4 = "PRIVMSG " nocase
        $irc5 = "NOTICE " nocase
        $irc6 = "QUIT " nocase
        $irc7 = "PART " nocase
        
        // Bot-specific indicators
        $bot1 = "bot" nocase
        $bot2 = "zombie" nocase
        $bot3 = "slave" nocase
        $bot4 = "drone" nocase
        
        // Bot commands
        $cmd1 = "!cmd" nocase
        $cmd2 = "!download" nocase
        $cmd3 = "!execute" nocase
        $cmd4 = "!update" nocase
        $cmd5 = "!spread" nocase
        $cmd6 = "!ddos" nocase
        $cmd7 = "!scan" nocase
        $cmd8 = "!info" nocase
        
        // IRC ports
        $port_6667 = ":6667"   // Default IRC port
        $port_6697 = ":6697"   // IRC SSL port
        $port_194 = ":194"     // IRC port
        
        // Channel names (common in botnets)
        $channel1 = "#bot" nocase
        $channel2 = "#warez" nocase
        $channel3 = "#hack" nocase
        $channel4 = "#exploit" nocase
        
    condition:
        (3 of ($irc*)) and 
        (any of ($bot*) or any of ($cmd*) or any of ($port_*) or any of ($channel*))
}

rule remote_access_tools {
    meta:
        author = "Joaquin Villegas"
        description = "Detects remote access tools and backdoor communications"
        category = "network"
        severity = "high"
        date = "2025.07.15"
    
    strings:
        // RAT names
        $rat1 = "teamviewer" nocase
        $rat2 = "anydesk" nocase
        $rat3 = "remote desktop" nocase
        $rat4 = "vnc" nocase
        $rat5 = "rdp" nocase
        
        // Suspicious RAT indicators
        $backdoor1 = "backdoor" nocase
        $backdoor2 = "trojan" nocase
        $backdoor3 = "rat" nocase
        $backdoor4 = "remote access" nocase
        
        // Network functions
        $network1 = "bind" nocase
        $network2 = "listen" nocase
        $network3 = "accept" nocase
        $network4 = "connect" nocase
        $network5 = "socket" nocase
        
        // Remote control functions
        $control1 = "shell" nocase
        $control2 = "cmd.exe" nocase
        $control3 = "/bin/sh" nocase
        $control4 = "reverse_shell" nocase
        $control5 = "bind_shell" nocase
        
        // Common backdoor ports
        $port1 = ":31337"   // Elite/leet port
        $port2 = ":12345"   // Common backdoor port
        $port3 = ":54321"   // Reverse of 12345
        $port4 = ":1337"    // Leet port
        $port5 = ":4444"    // Metasploit default
        
    condition:
        (any of ($rat*) and any of ($backdoor*)) or
        (any of ($network*) and 2 of ($control*)) or
        (2 of ($port*))
}

rule cryptocurrency_mining_network {
    meta:
        author = "Joaquin Villegas"
        description = "Detects cryptocurrency mining network communications"
        category = "network"
        severity = "medium"
        date = "2025.07.15"
    
    strings:
        // Cryptocurrency types
        $crypto1 = "bitcoin" nocase
        $crypto2 = "ethereum" nocase
        $crypto3 = "monero" nocase
        $crypto4 = "litecoin" nocase
        $crypto5 = "dogecoin" nocase
        
        // Mining indicators
        $mining1 = "mining" nocase
        $mining2 = "miner" nocase
        $mining3 = "hashrate" nocase
        $mining4 = "stratum" nocase
        $mining5 = "getwork" nocase
        
        // Mining pool indicators
        $pool1 = "pool" nocase
        $pool2 = "nanopool" nocase
        $pool3 = "ethermine" nocase
        $pool4 = "antpool" nocase
        $pool5 = "f2pool" nocase
        
        // Mining protocols
        $protocol1 = "stratum+tcp" nocase
        $protocol2 = "stratum+ssl" nocase
        
        // Performance indicators
        $perf1 = "100%" nocase
        $perf2 = "cpu usage" nocase
        $perf3 = "gpu usage" nocase
        
        // Common mining ports
        $port1 = ":4444"    // Stratum port
        $port2 = ":3333"    // Mining port
        $port3 = ":8080"    // Alternative mining port
        
    condition:
        (any of ($crypto*) and any of ($mining*)) and
        (any of ($pool*) or any of ($protocol*) or any of ($port*)) and
        any of ($perf*)
}

rule network_reconnaissance {
    meta:
        author = "Joaquin Villegas"
        description = "Detects network reconnaissance and scanning activities"
        category = "network"
        severity = "medium"
        date = "2025.07.15"
    
    strings:
        // Scanning tools
        $scan1 = "nmap" nocase
        $scan2 = "masscan" nocase
        $scan3 = "zmap" nocase
        $scan4 = "portscan" nocase
        $scan5 = "port scan" nocase
        
        // Reconnaissance activities
        $recon1 = "reconnaissance" nocase
        $recon2 = "enumeration" nocase
        $recon3 = "discovery" nocase
        $recon4 = "fingerprint" nocase
        
        // Network probing
        $probe1 = "ping sweep" nocase
        $probe2 = "host discovery" nocase
        $probe3 = "service detection" nocase
        $probe4 = "version detection" nocase
        
        // Vulnerability scanning
        $vuln1 = "vulnerability" nocase
        $vuln2 = "exploit" nocase
        $vuln3 = "cve" nocase
        $vuln4 = "security scan" nocase
        
        // Target patterns
        $target1 = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}/ // CIDR notation
        $target2 = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9-*]+/              // IP range
        
    condition:
        (any of ($scan*) or any of ($recon*) or any of ($probe*)) and
        (any of ($vuln*) or any of ($target*))
}