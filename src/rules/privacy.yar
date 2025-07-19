/*
    Privacy and Data Theft Detection Rules
    Author: Joaquin Villegas
    Description: Comprehensive YARA rules to detect data exfiltration and privacy violations
    Date: 2025.07.15
*/

rule credential_harvesting {
    meta:
        author = "Joaquin Villegas"
        description = "Detects files containing harvested credentials"
        category = "privacy"
        severity = "high"
        date = "2025.07.15"
    
    strings:
        $cred1 = "password" nocase
        $cred2 = "passwd" nocase
        $cred3 = "pwd" nocase
        $cred4 = "username" nocase
        $cred5 = "user" nocase
        $cred6 = "login" nocase
        $cred7 = "email" nocase
 
        $token1 = "api_key" nocase
        $token2 = "access_token" nocase
        $token3 = "secret_key" nocase
        $token4 = "private_key" nocase
        $token5 = "auth_token" nocase
        $token6 = "bearer" nocase
        
        $delim1 = ":"
        $delim2 = "="
        $delim3 = ","
        $delim4 = ";"
        
        $email_pattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/
        
        $pass_pattern1 = /password[:\s]*[a-zA-Z0-9!@#$%^&*()_+-=]{6,}/i
        $pass_pattern2 = /pwd[:\s]*[a-zA-Z0-9!@#$%^&*()_+-=]{6,}/i
        
    condition:
        (3 of ($cred*) or 2 of ($token*)) and 
        any of ($delim*) and 
        ($email_pattern or any of ($pass_pattern*))
}

rule browser_data_theft {
    meta:
        author = "Joaquin Villegas"
        description = "Detects browser data theft attempts"
        category = "privacy"
        severity = "high"
        date = "2025.07.15"
    
    strings:
        $browser1 = "Chrome" nocase
        $browser2 = "Firefox" nocase
        $browser3 = "Safari" nocase
        $browser4 = "Edge" nocase
        $browser5 = "Opera" nocase
        $browser6 = "Brave" nocase
        
        $data1 = "cookies" nocase
        $data2 = "history" nocase
        $data3 = "bookmarks" nocase
        $data4 = "passwords" nocase
        $data5 = "autofill" nocase
        $data6 = "localStorage" nocase
        $data7 = "sessionStorage" nocase
        
        $db1 = "Login Data" nocase
        $db2 = "Web Data" nocase
        $db3 = "History" nocase
        $db4 = "Cookies" nocase
        $db5 = "places.sqlite" nocase
        $db6 = "logins.json" nocase
        
        $profile1 = "Default/Login Data"
        $profile2 = "Profile 1/Login Data"
        $profile3 = "User Data" nocase
        $profile4 = ".mozilla" nocase
        
    condition:
        any of ($browser*) and 
        (2 of ($data*) or any of ($db*) or any of ($profile*))
}

rule ssh_key_extraction {
    meta:
        author = "Joaquin Villegas"
        description = "Detects SSH key extraction attempts"
        category = "privacy"
        severity = "high"
        date = "2025.07.15"
    
    strings:
        $ssh1 = "id_rsa" nocase
        $ssh2 = "id_dsa" nocase
        $ssh3 = "id_ecdsa" nocase
        $ssh4 = "id_ed25519" nocase
        $ssh5 = "authorized_keys" nocase
        $ssh6 = "known_hosts" nocase
        
        $ssh_dir = ".ssh" nocase
        
        $private_key1 = "-----BEGIN PRIVATE KEY-----"
        $private_key2 = "-----BEGIN RSA PRIVATE KEY-----"
        $private_key3 = "-----BEGIN DSA PRIVATE KEY-----"
        $private_key4 = "-----BEGIN EC PRIVATE KEY-----"
        $private_key5 = "-----BEGIN OPENSSH PRIVATE KEY-----"
        
        $public_key1 = "ssh-rsa"
        $public_key2 = "ssh-dss"
        $public_key3 = "ssh-ed25519"
        $public_key4 = "ecdsa-sha2"
        
    condition:
        any of ($ssh*) or 
        $ssh_dir or 
        any of ($private_key*) or 
        2 of ($public_key*)
}

rule email_harvesting {
    meta:
        author = "Joaquin Villegas"
        description = "Detects email harvesting and contact list theft"
        category = "privacy"
        severity = "medium"
        date = "2025.07.15"
    
    strings:
        $email_pattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/
        
        $contact1 = "contact list" nocase
        $contact2 = "address book" nocase
        $contact3 = "email list" nocase
        $contact4 = "mailing list" nocase
        $contact5 = "subscribers" nocase
        
        $format1 = ".csv" nocase
        $format2 = ".txt" nocase
        $format3 = ".json" nocase
        $format4 = ".xml" nocase

        $client1 = "outlook" nocase
        $client2 = "thunderbird" nocase
        $client3 = "gmail" nocase
        $client4 = "apple mail" nocase
        
    condition:
        @email_pattern[10] and
        (any of ($contact*) or any of ($format*) or any of ($client*))
}

rule personal_data_collection {
    meta:
        author = "Joaquin Villegas"
        description = "Detects personal identifiable information collection"
        category = "privacy"
        severity = "high"
        date = "2025.07.15"
    
    strings:
        $pii1 = "social security" nocase
        $pii2 = "ssn" nocase
        $pii3 = "social security number" nocase
        $pii4 = "credit card" nocase
        $pii5 = "phone number" nocase
        $pii6 = "address" nocase
        $pii7 = "birthday" nocase
        $pii8 = "date of birth" nocase
        $pii9 = "driver license" nocase
        $pii10 = "passport" nocase
        
        $ssn_pattern = /\b\d{3}-\d{2}-\d{4}\b/
        $credit_card = /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/
        $phone_pattern = /\b\d{3}-\d{3}-\d{4}\b/
        $zip_pattern = /\b\d{5}(-\d{4})?\b/
        
        $doc1 = "medical records" nocase
        $doc2 = "financial records" nocase
        $doc3 = "tax returns" nocase
        $doc4 = "insurance" nocase
        
    condition:
        (3 of ($pii*) or any of ($ssn_pattern, $credit_card, $phone_pattern)) and
        (any of ($doc*) or $zip_pattern)
}

rule cloud_storage_exfiltration {
    meta:
        author = "Joaquin Villegas"
        description = "Detects data exfiltration to cloud storage services"
        category = "privacy"
        severity = "medium"
        date = "2025.07.15"
    
    strings:
        $cloud1 = "dropbox" nocase
        $cloud2 = "google drive" nocase
        $cloud3 = "onedrive" nocase
        $cloud4 = "icloud" nocase
        $cloud5 = "box.com" nocase
        $cloud6 = "mega.nz" nocase
        $cloud7 = "mediafire" nocase
        $cloud8 = "wetransfer" nocase
        
        $upload1 = "upload" nocase
        $upload2 = "sync" nocase
        $upload3 = "backup" nocase
        $upload4 = "share" nocase
        
        $file_type1 = ".db" nocase
        $file_type2 = ".sql" nocase
        $file_type3 = ".csv" nocase
        $file_type4 = ".xlsx" nocase
        $file_type5 = ".dat" nocase
        
        $api1 = "api.dropboxapi.com"
        $api2 = "www.googleapis.com"
        $api3 = "graph.microsoft.com"
        
    condition:
        any of ($cloud*) and 
        any of ($upload*) and 
        (any of ($file_type*) or any of ($api*))
}

rule financial_data_theft {
    meta:
        author = "Joaquin Villegas"
        description = "Detects financial data and banking information theft"
        category = "privacy"
        severity = "critical"
        date = "2025.07.15"
    
    strings:
        $bank1 = "account number" nocase
        $bank2 = "routing number" nocase
        $bank3 = "iban" nocase
        $bank4 = "swift code" nocase
        $bank5 = "sort code" nocase
        
        $fin1 = "bank of america" nocase
        $fin2 = "wells fargo" nocase
        $fin3 = "chase" nocase
        $fin4 = "citibank" nocase
        $fin5 = "paypal" nocase
        $fin6 = "venmo" nocase
        
        $cc1 = "card number" nocase
        $cc2 = "cvv" nocase
        $cc3 = "expiry" nocase
        $cc4 = "expiration date" nocase
        $cc5 = "cardholder" nocase
        
        $account_pattern = /account[:\s]*\d{8,}/i
        $routing_pattern = /routing[:\s]*\d{9}/i
        
    condition:
        (2 of ($bank*) or 2 of ($cc*)) and 
        (any of ($fin*) or any of ($account_pattern, $routing_pattern))
}

rule session_token_theft {
    meta:
        author = "Joaquin Villegas"
        description = "Detects session token and authentication data theft"
        category = "privacy"
        severity = "high"
        date = "2025.07.15"
    
    strings:
        $session1 = "session_id" nocase
        $session2 = "sessionid" nocase
        $session3 = "jsessionid" nocase
        $session4 = "phpsessid" nocase
        $session5 = "aspsessionid" nocase
        
        $auth1 = "access_token" nocase
        $auth2 = "refresh_token" nocase
        $auth3 = "bearer_token" nocase
        $auth4 = "oauth_token" nocase
        $auth5 = "jwt" nocase

        $cookie1 = "Set-Cookie" nocase
        $cookie2 = "Cookie:" nocase
        $cookie3 = "HttpOnly" nocase
        $cookie4 = "Secure" nocase
        
        $jwt_pattern = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/
        $bearer_pattern = /Bearer\s+[A-Za-z0-9_-]{20,}/
        
    condition:
        (any of ($session*) or any of ($auth*)) and 
        (any of ($cookie*) or any of ($jwt_pattern, $bearer_pattern))
}