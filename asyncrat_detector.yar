rule AsyncRAT_Meccha_Camouflage_Crypter {
    meta:
        description = "Detects the custom .NET crypter stub (meccha-camouflageV3) used to encapsulate AsyncRAT payloads"
        author = "SOC Analyst"
        date = "2026-07-16"
        threat_family = "AsyncRAT / Trojan.MSIL.Crypter"
        malware_sample_sha256 = "0aac658075b7d9e81419d0beaa3db796569bc14fd57512f4479fb36e9cc4c1a2"
    strings:
        $mscoree = "mscoree.dll" ascii wide
        $pdb_path = "MecchaCamouflage\\v3\\obj\\Release\\meccha-camouflageV3.pdb" ascii wide
        $orig_name = "meccha-camouflageV3.exe" ascii wide
        $anti_sandbox_url = "http://ip-api.com" ascii wide
        $wmi_comp = "Select * from Win32_ComputerSystem" ascii wide
        $wmi_av = "Select * from AntivirusProduct" ascii wide
        $wmi_video = "SELECT * FROM Win32_VideoController" ascii wide
        $api_critical = "RtlSetProcessIsCritical" ascii wide
        $api_debugger = "CheckRemoteDebuggerPresent" ascii wide
        $api_hook = "SetWindowsHookEx" ascii wide
    condition:
        uint16(0) == 0x5A4D and $mscoree and (($pdb_path or $orig_name) or ($anti_sandbox_url and 2 of ($wmi_*)) or (2 of ($api_*)))
}
