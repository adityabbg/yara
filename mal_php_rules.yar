// YARA rules generated on 2025-08-11
// Targets: Uploaded PHP webshell/backdoor variants
// Notes: Each rule includes both robust string patterns and exact SHA-256
//        file-hash matches for these specific samples.

import "hash"

rule PHP_AnimeSecretPortal_Backdoor_0f7d201a
{
    meta:
        author = "GPT-5 Thinking"
        date = "2025-08-11"
        description = "Backdoor that pulls payload from GitHub (rezahaxor1337) and evals it; themed 'Anime Secret Portal'."
        sha256_sample_1 = "0f7d201a79629a0eb72f204735d2904123d3b6e57821fdc82bb3bec0f8bc127c"
        sha256_sample_2 = "0f7d201a79629a0eb72f204735d2904123d3b6e57821fdc82bb3bec0f8bc127c"
        family = "php_remote_loader"
    strings:
        $title = "<title>Anime Secret Portal</title>" ascii
        $repo1 = "rezahaxor1337/shell" ascii
        $repo2 = "biru-1337.txt" ascii
        $evalp = "eval('?>' . $payload);" ascii
        $curl1 = "curl_init" ascii
        $curl2 = "curl_exec" ascii
    condition:
        // Match exact sample hash OR strong string combo
        hash.sha256(0, filesize) == sha256_sample_1 or
        hash.sha256(0, filesize) == sha256_sample_2 or
        (uint16(0) == 0x3f3c and $evalp and any of ($repo*) and $title)
}

rule PHP_CyberAuthPortal_RemoteLoader_ad142af2
{
    meta:
        author = "GPT-5 Thinking"
        date = "2025-08-11"
        description = "Password-gated portal that fetches PHP from dpaste and evals it ('CYBER-AUTH PORTAL')."
        sha256_sample = "ad142af2364a9202a249c0f637205e23cca2291f4b06950331723d9eec70980f"
        family = "php_remote_loader"
    strings:
        $title = "<title>CYBER-AUTH PORTAL</title>" ascii
        $dpaste = "dpaste.org" ascii
        $evalc = "eval('?>' . $content);" ascii
        $phash = "passwordHash" ascii
    condition:
        hash.sha256(0, filesize) == sha256_sample or
        (uint16(0) == 0x3f3c and $evalc and $dpaste and $title)
}

rule PHP_Obfuscated_Gzinflate_Base64_5433eac9
{
    meta:
        author = "GPT-5 Thinking"
        date = "2025-08-11"
        description = "Obfuscated PHP using base64 + gzinflate decoded then eval'd via htmlspecialchars_decode."
        sha256_sample = "5433eac93e9b798271742ac00286c908e633fc4e633710d42ce75e027672990c"
        family = "php_obfuscated_loader"
    strings:
        $gzi = "gzinflate(base64_decode(" ascii
        $evh = "eval(htmlspecialchars_decode(" ascii
        $stt = "$stt1" ascii
    condition:
        hash.sha256(0, filesize) == sha256_sample or
        (uint16(0) == 0x3f3c and all of ($gzi, $evh))
}
