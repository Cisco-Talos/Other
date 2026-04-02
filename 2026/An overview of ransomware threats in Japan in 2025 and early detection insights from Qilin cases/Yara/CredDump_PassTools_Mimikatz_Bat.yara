rule CredDump_PassTools_Mimikatz_Bat
{
  meta:
    description = "Simple detection for BAT launching SharpDecryptPwd + Mimikatz, often with Pass tools (WebBrowserPassView/BypassCredGuard)"
    author= “Cisco Talos”

  strings:
    $s_wbpv = "\\Pass\\WebBrowserPassView.exe" nocase
    $s_bcg  = "\\Pass\\BypassCredGuard.exe" nocase
    $s_sdp  = "\\Pass\\SharpDecryptPwd" nocase

    $s_mimi1 = "\\Mimik\\x64\\mimikatz.exe" nocase
    $s_mimi2 = "\\Mimik\\x32\\mimikatz.exe" nocase

    $c1 = "sekurlsa::logonPasswords" nocase
    $c2 = "lsadump::secrets" nocase
    $c3 = "lsadump::sam" nocase
    $c4 = "lsadump::cache" nocase
    $c5 = "dpapi::chrome" nocase
    $c6 = "vault::cred" nocase
    $c7 = "token::elevate" nocase
    $c8 = "privilege::debug" nocase

  condition:
    filesize < 10KB and
    $s_sdp and ($s_mimi1 or $s_mimi2) and
    (
      1 of ($s_wbpv, $s_bcg) or
      2 of ($c*)
    )
}
