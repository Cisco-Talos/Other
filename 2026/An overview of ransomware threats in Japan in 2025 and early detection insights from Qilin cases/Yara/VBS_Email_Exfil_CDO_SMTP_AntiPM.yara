rule VBS_Email_Exfil_CDO_SMTP_AntiPM
{
  meta:
    description = "Generic detection for VBScript using CDO.Message with SMTP configuration and attachment (potential email exfiltration) with specific SMTP domain"
    author = "Cisco Talos"
    confidence = "medium"

  strings:
    $cdo1 = "CreateObject(\"CDO.Message\")" nocase
    $cdo2 = "CDO.Message" nocase
    $schema = "http://schemas.microsoft.com/cdo/configuration/" nocase

    $f_sendusing   = "sendusing" nocase
    $f_smtpserver  = "smtpserver" nocase
    $f_smtpport    = "smtpserverport" nocase
    $f_smtpauth    = "smtpauthenticate" nocase
    $f_user        = "sendusername" nocase
    $f_pass        = "sendpassword" nocase
    $f_usessl      = "smtpusessl" nocase
    $f_timeout     = "smtpconnectiontimeout" nocase

    $attach = ".AddAttachment" nocase
    $send1  = ".send" nocase
    $send2  = "send" nocase

    $wscript = "WScript." nocase
    $fso     = "Scripting.FileSystemObject" nocase

    // Added to reduce false positives
    $smtp_domain = "mail.anti.pm" nocase

  condition:
    filesize < 50KB and
    ( $cdo1 or $cdo2 ) and
    $schema and

    4 of ($f_*) and

    $attach and
    ( $send1 or $send2 ) and

    1 of ($wscript, $fso) and

    $smtp_domain
}
