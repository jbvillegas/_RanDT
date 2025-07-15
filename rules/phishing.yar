rule phising {
    meta:
        description = "Rule that detects phishing attempts based on specific patterns in the content."
        author = "Joaquin Villegas"
        date = "2025.07.15"
    
    strings: 
        $eml = "From:" nocase
        $eml1 = "To:" nocase
        $eml2 = "Subject: " nocase 

        $phis_subject = "urgent account verification" nocase
        $phis_subject1 = "account security alert" nocase
        $phis_subject2 = "action necessary" nocase

        $phis_body = "dear user" nocase
        $phis_body1 = "hello sir/madam" nocase
        $phis_body2 = "account holder" nocase
        $phis_body3 = "attention" nocase

        $clck = "click" nocase
        $clck1 = "confirm" nocase
        $clck2 = "verify" nocase
        $clck3 = "here" nocase
        $clck4 = "now" nocase
        $clck5 = "change password" nocase

        $pmtp = "unautorhized" nocase
        $pmtp1 = "expired" nocase
        $pmtp2 = "deleted" nocase
        $pmtp3 = "suspended" nocase
        $pmtp4 = "revoked" nocase
        $pmtp5 = "unable" nocase
    
    condition: 
        all of ($eml*) and
        any of ($phis_subject*) and
        any of ($phis_body*) and
        any of ($clck*) and 
        any of ($pmtp*)
}