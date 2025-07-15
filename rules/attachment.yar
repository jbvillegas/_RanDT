rule with_attachment: mail {
    meta:
        author = "Joaquin Villegas"
        description = "Detects emails with attachments based on patterns and extensions."
    strings: 
        $attachment = /Content-Disposition:\s*attachment/i //regex pattern http
        $inline = /Content-Disposition:\s*inline/i //regex pattern for inline attachments

        $ext1 = /filename="[^"]*\.exe"/i
        $ext2 = /filename="[^"]*\.scr"/i
        $ext3 = /filename="[^"]*\.bat"/i
        $ext4 = /filename="[^"]*\.cmd"/i
        $ext5 = /filename="[^"]*\.com"/i
        $ext6 = /filename="[^"]*\.pif"/i
        $ext7 = /filename="[^"]*\.vbs"/i
        $ext8 = /filename="[^"]*\.js"/i

        $double_ext1 = /filename="[^"]*\.pdf\.exe"/i
        $double_ext2 = /filename="[^"]*\.doc\.exe"/i
        $double_ext3 = /filename="[^"]*\.jpg\.exe"/i
        $double_ext4 = /filename="[^"]*\.txt\.scr"/i

        
        $mime_exe = "Content-Type: application/octet-stream"
        $mime_script = "Content-Type: application/javascript"
        $mime_zip = "Content-Type: application/zip"

        
        $base64_header = "Content-Transfer-Encoding: base64"
        $base64_pattern = /[A-Za-z0-9+\/]{76}/  

        $zip_with_exe = /filename="[^"]*\.zip".*\.exe/i
        $rar_with_exe = /filename="[^"]*\.rar".*\.exe/i
    condition:
        ($attachment or $inline) and
        (
            any of ($ext*) or
            any of ($double_ext*) or
            $mime_exe or
            $mime_script or
            $mime_zip or
            $base64_header or
            $base64_pattern or
            $zip_with_exe or
            $rar_with_exe
        )
}

rule without_attachment: mail {
    meta:
        author = "Joaquin Villegas"
        description = "Detects emails without attachments"
    strings: 
        $email_01 = "From:"
        $email_02 = "To:"
        $email_03 = "Subject:"
        $attachment = /Content-Disposition:\s*attachment/i
    condition:
        $email_01 and $email_02 and $email_03 and not $attachment
}

rule attachment_size: mail {
    meta:
        author = "Joaquin Villegas"
    strings:
        $attachment = "Content-Disposition: attachment" nocase
        $filename = "filename=" nocase

    condition:
        $attachment and
        filesize > 50MB or 
        (filesize < 1KB and filesize > 0) // Adjusted to detect attachments smaller than 1KB
}