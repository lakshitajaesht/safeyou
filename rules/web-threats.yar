rule credential_phishing_language : phishing web
{
  meta:
    description = "Credential theft and account verification language"
    severity = 24
  strings:
    $verify = "verify your account" nocase
    $suspend = "account will be suspended" nocase
    $confirm = "confirm your identity" nocase
    $password = "password" nocase
    $signin = "sign in" nocase
  condition:
    2 of them
}

rule crypto_wallet_theft : phishing crypto
{
  meta:
    description = "Cryptocurrency wallet recovery or seed phrase request"
    severity = 35
  strings:
    $seed1 = "seed phrase" nocase
    $seed2 = "recovery phrase" nocase
    $wallet = "connect wallet" nocase
    $private = "private key" nocase
  condition:
    any of ($seed*) or ($wallet and $private)
}

rule javascript_obfuscation_redirect : malware javascript
{
  meta:
    description = "Obfuscated JavaScript combined with browser redirection"
    severity = 28
  strings:
    $eval = "eval(" nocase
    $atob = "atob(" nocase
    $fromchar = "fromCharCode" nocase
    $location1 = "window.location" nocase
    $location2 = "location.replace" nocase
  condition:
    1 of ($eval, $atob, $fromchar) and 1 of ($location*)
}

rule fake_security_alert : scareware web
{
  meta:
    description = "Fake browser or device security warning language"
    severity = 20
  strings:
    $infected = "your device is infected" nocase
    $virus = "virus detected" nocase
    $support = "call support" nocase
    $urgent = "immediate action required" nocase
  condition:
    2 of them
}

rule suspicious_download_script : malware javascript
{
  meta:
    description = "Script patterns associated with forced payload downloads"
    severity = 22
  strings:
    $blob = "createObjectURL" nocase
    $download = ".download" nocase
    $click = ".click()" nocase
    $base64 = "base64" nocase
  condition:
    3 of them
}

rule hidden_collection_form : phishing web
{
  meta:
    description = "Hidden form fields collecting credential or payment data"
    severity = 18
  strings:
    $hidden = "type=\"hidden\"" nocase
    $password = "type=\"password\"" nocase
    $card = "card number" nocase
    $cvv = "cvv" nocase
  condition:
    $hidden and 2 of ($password, $card, $cvv)
}
