rule Cryptic_Demo_Infostealer_Lead : attack.t1555 attack.t1539 infostealer demo
{
    meta:
        description = "Demo rule for infostealer lead text validation"
        author = "cryptic-cti"
        date = "2026-06-17"
        threat_name = "Infostealer lead"
    strings:
        $redline = "RedLine"
        $lumma = "Lumma"
        $cookies = "cookies"
    condition:
        any of them
}
