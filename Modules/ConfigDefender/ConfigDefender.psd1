@{
    GUID = 'C46BE3DC-30A9-452F-A5FD-4BF9CA87A854'
    Author="Microsoft Corporation"
    CompanyName="Microsoft Corporation"
    Copyright="Copyright (C) Microsoft Corporation. All rights reserved."
    ModuleVersion = '1.0'
    NestedModules = @( 'MSFT_MpComputerStatus.cdxml',
                       'MSFT_MpPreference.cdxml',
                       'MSFT_MpThreat.cdxml',
                       'MSFT_MpThreatCatalog.cdxml',
                       'MSFT_MpThreatDetection.cdxml',
                       'MSFT_MpScan.cdxml',
                       'MSFT_MpSignature.cdxml',
                       'MSFT_MpWDOScan.cdxml',
                       'MSFT_MpRollback.cdxml'
                       )

    FunctionsToExport = @( 'Get-MpPreference',
                           'Set-MpPreference',
                           'Add-MpPreference',
                           'Remove-MpPreference',
                           'Get-MpComputerStatus',
                           'Get-MpThreat',
                           'Get-MpThreatCatalog',
                           'Get-MpThreatDetection',
                           'Start-MpScan',
                           'Update-MpSignature',
                           'Remove-MpThreat',
                           'Start-MpWDOScan',
                           'Start-MpRollback'
                           )
    HelpInfoUri="http://go.microsoft.com/fwlink/?linkid=390762"
    PowerShellVersion = '3.0'
}

# SIG # Begin signature block
# MIIljwYJKoZIhvcNAQcCoIIlgDCCJXwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAKi/54AHWcDKN7
# MMgzW+Je4GnjudtlwpnXzX+Iejz1QKCCC14wggTrMIID06ADAgECAhMzAAAI/yN0
# 5bNiDD7eAAAAAAj/MA0GCSqGSIb3DQEBCwUAMHkxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBXaW5kb3dzIFBD
# QSAyMDEwMB4XDTIxMDkwOTE5MDUxNloXDTIyMDkwMTE5MDUxNlowcDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEaMBgGA1UEAxMRTWljcm9zb2Z0
# IFdpbmRvd3MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7XnnM3dQr
# TkdEfd2ofYS42n2ZaluJCuT4F9PWFdlYA482HzK5e+7TSWW4AWxdYIM1qGM4fDRr
# 7tFBF+T6sChm9RFlnHsYEOovf0T62DEQuOUIleyAuq8MgtrV4X2GOiMvIYsoYFIQ
# cQpCbeHAXFFniWwJOG7sEZe0wWvxImHKot1//FPG/dR3HMZhXnAFWlXuJ6SAQOqY
# E4wF9x5Yl/1nAxjp+QbwR75w2vHYgrdZhvGMF5jrLJJOr+UtrrINYi2/Hs50XFHN
# 6nmh4iGjjUlRaFR93M9OepSDVIM6gEBZYiO0X/iR1w/B6s0tYs8fQgkc+jAcGVTt
# IRfNEydMVtBRAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEEAYI3CgMGBggr
# BgEFBQcDAzAdBgNVHQ4EFgQUNBYlRvj/2BU45L0EYOW4Irw3QbowUAYDVR0RBEkw
# R6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNv
# MRYwFAYDVQQFEw0yMzAwMjgrNDY3NjAwMB8GA1UdIwQYMBaAFNFPqYoHCM70JBiY
# 5QD/89Z5HTe8MFMGA1UdHwRMMEowSKBGoESGQmh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1dpblBDQV8yMDEwLTA3LTA2LmNybDBX
# BggrBgEFBQcBAQRLMEkwRwYIKwYBBQUHMAKGO2h0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2kvY2VydHMvTWljV2luUENBXzIwMTAtMDctMDYuY3J0MAwGA1UdEwEB
# /wQCMAAwDQYJKoZIhvcNAQELBQADggEBADGfbGe9r+UZf8Qyfwku39aesTNARnzn
# wh17YDoFuqmdLT1A4SYEqnvl7xE4iGjvbV+jQjnkkyIA1B2ZOuhMEFIfdmtFkD0p
# ENenaq3Kx5EBQ3bb5jOmckp8UmcJ2Ej2XF7ZwYv2qcxNUZLE2fcl0B3INjXGGYP1
# nNYdheBa9z9tbOv/KRYxUQ1/od+vzHGPuypV/RQKIq6GnO0m7GkYe5HEn4ROn2KC
# 7xHnTIYH69EjONUt0zBtjgTb6l66TxcuORzOffGpkdmnY3TOwkJQGuPNIRGsUZpS
# KrA6s9EGC9wXYQwZqsNt5Hdawzx92CLMVjfkNP4BjJ26+1ovK6/P2xMwggZrMIIE
# U6ADAgECAgphDGoZAAAAAAAEMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9v
# dCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0xMDA3MDYyMDQwMjNaFw0y
# NTA3MDYyMDUwMjNaMHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xIzAhBgNVBAMTGk1pY3Jvc29mdCBXaW5kb3dzIFBDQSAyMDEwMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwHm7OrHwD4S4rWQqdRZz0LsH9j4NnRTk
# sZ/ByJSwOHwf0DNV9bojZvUuKEhTxxaDuvVRrH6s4CZ/D3T8WZXcycai91JwWiwd
# lKsZv6+Vfa9moW+bYm5tS7wvNWzepGpjWl/78w1NYcwKfjHrbArQTZcP/X84RuaK
# x3NpdlVplkzk2PA067qxH84pfsRPnRMVqxMbclhiVmyKgaNkd5hGZSmdgxSlTAig
# g9cjH/Nf328sz9oW2A5yBCjYaz74E7F8ohd5T37cOuSdcCdrv9v8HscH2MC+C5Me
# KOBzbdJU6ShMv2tdn/9dMxI3lSVhNGpCy3ydOruIWeGjQm06UFtI0QIDAQABo4IB
# 4zCCAd8wEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFNFPqYoHCM70JBiY5QD/
# 89Z5HTe8MBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAP
# BgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjE
# MFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kv
# Y3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEF
# BQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MIGdBgNVHSAEgZUw
# gZIwgY8GCSsGAQQBgjcuAzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5taWNy
# b3NvZnQuY29tL1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcCAjA0
# HjIgHQBMAGUAZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUAbgB0
# AC4gHTANBgkqhkiG9w0BAQsFAAOCAgEALkGmhrUGb/CAhfo7yhfpyfrkOcKUcMNk
# lMPYVqaQjv7kmvRt9W+OU41aqPOu20Zsvn8dVFYbPB1xxFEVVH6/7qWVQjP9DZAk
# JOP53JbK/Lisv/TCOVa4u+1zsxfdfoZQI4tWJMq7ph2ahy8nheehtgqcDRuM8wBi
# QbpIdIeC/VDJ9IcpwwOqK98aKXnoEiSahu3QLtNAgfUHXzMGVF1AtfexYv1NSPdu
# QUdSHLsbwlc6qJlWk9TG3iaoYHWGu+xipvAdBEXfPqeE0VtEI2MlNndvrlvcItUU
# I2pBf9BCptvvJXsE49KWN2IGr/gbD46zOZq7ifU1BuWkW8OMnjdfU9GjN/2kT+gb
# Dmt25LiPsMLq/XX3LEG3nKPhHgX+l5LLf1kDbahOjU6AF9TVcvZW5EifoyO6BqDA
# jtGIT5Mg8nBf2GtyoyBJ/HcMXcXH4QIPOEIQDtsCrpo3HVCAKR6kp9nGmiVV/UDK
# rWQQ6DH5ElR5GvIO2NarHjP+AucmbWFJj/Elwot0md/5kxqQHO7dlDMOQlDbf1D4
# n2KC7KaCFnxmvOyZsMFYXaiwmmEUkdGZL0nkPoGZ1ubvyuP9Pu7sCYYDBw0bDXzr
# 9FrJlc+HEgpd7MUCks0FmXLKffEqEBg45DGjKLTmTMVSo5xqx33AcQkEDXDeAj+H
# 7lah7Ou1TIUxghmHMIIZgwIBATCBkDB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSMwIQYDVQQDExpNaWNyb3NvZnQgV2luZG93cyBQQ0EgMjAx
# MAITMwAACP8jdOWzYgw+3gAAAAAI/zANBglghkgBZQMEAgEFAKCBrjAZBgkqhkiG
# 9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIB
# FTAvBgkqhkiG9w0BCQQxIgQgf4HSYirBYS8rRlxdxE/ZzT4V6oDLhexZCKppWord
# OAswQgYKKwYBBAGCNwIBDDE0MDKgFIASAE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbTANBgkqhkiG9w0BAQEFAASCAQBm8/JivvjE
# Z18WY+fZ8mDzXch3WqFz4apnDfvUZ65Z0c3SBIt+LOWFhXw3BiIBlPWloRx5sbkL
# 95e7KjV34+NDc+/fBurHYUeQjqOrVLvOBUi3d4SdGU5LDbSkNMfER6NbGcgn2a/z
# mXbFUmA23xGGh3faPHiFzuH4vR5Bsh7cjD9+3M23FfMBXpcAKwjOg3spfdnTtMLg
# 17z4DFAW7h0s+f26AVJ3mwQwV3KheYS836b2nKPJEhsMMbfg8JYZsfUKeng/Uvil
# Wihj3N9x1/FoBktejCZ5H5SacYZi08rLstD8WKjY6HvD5s0Q00o3SnSBDobVZeiw
# 2Bosr9wIOF6foYIXFjCCFxIGCisGAQQBgjcDAwExghcCMIIW/gYJKoZIhvcNAQcC
# oIIW7zCCFusCAQMxDzANBglghkgBZQMEAgEFADCCAVkGCyqGSIb3DQEJEAEEoIIB
# SASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIFDxEjxQ
# NSxXeeBLorZJHjKWq5ki8i97+cSkq8fxGeG7AgZiMvskSQQYEzIwMjIwMzMxMjIz
# NzMxLjA1NlowBIACAfSggdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlv
# bnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0JENC00QjgwLTY5
# QzMxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WgghFlMIIH
# FDCCBPygAwIBAgITMwAAAYm0v4YwhBxLjwABAAABiTANBgkqhkiG9w0BAQsFADB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMTEwMjgxOTI3NDFaFw0y
# MzAxMjYxOTI3NDFaMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0
# ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjNCRDQtNEI4MC02OUMzMSUwIwYD
# VQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEAvQZXxZFma6plmuOyvNpV8xONOwcYolZG/BjyZWGS
# k5JOGaLyrKId5VxVHWHlsmJE4SvnzsdpsKmVx8otONveIUFvSceEZp8VXmu5m1fu
# 8L7c+3lwXcibjccqtEvtQslokQVx0r+L54abrNDarwFG73IaRidIS1i9c+unJ8oY
# yhDRLrCysFAVxyQhPNZkWK7Z8/VGukaKLAWHXCh/+R53h42gFL+9/mAALxzCXXuo
# fi8f/XKCm7xNwVc1hONCCz6oq94AufzVNkkIW4brUQgYpCcJm9U0XNmQvtropYDn
# 9UtY8YQ0NKenXPtdgLHdQ8Nnv3igErKLrWI0a5n5jjdKfwk+8mvakqdZmlOseeOS
# 1XspQNJAK1uZllAITcnQZOcO5ofjOQ33ujWckAXdz+/x3o7l4AU/TSOMzGZMwhUd
# tVwC3dSbItpSVFgnjM2COEJ9zgCadvOirGDLN471jZI2jClkjsJTdgPk343TQA4J
# Fvds/unZq0uLr+niZ3X44OBx2x+gVlln2c4UbZXNueA4yS1TJGbbJFIILAmTUA9A
# uj5eISGTbNiyWx79HnCOTar39QEKozm4LnTmDXy0/KI/H/nYZGKuTHfckP28wQS0
# 6rD+fDS5xLwcRMCW92DkHXmtbhGyRilBOL5LxZelQfxt54wl4WUC0AdAEolPekOD
# wO8CAwEAAaOCATYwggEyMB0GA1UdDgQWBBSXbx+zR1p4IIAeguA6rHKkrfl7UDAf
# BgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQ
# hk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQl
# MjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBe
# MFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2Nl
# cnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAM
# BgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUA
# A4ICAQCOtLdpWUI4KwfLLrfaKrLB92DqbAspGWM41TaO4Jl+sHxPo522uu3GKQCj
# mkRWreHtlfyy9kOk7LWax3k3ke8Gtfetfbh7qH0LeV2XOWg39BOnHf6mTcZq7FYS
# ZZch1JDQjc98+Odlow+oWih0Dbt4CV/e19ZcE+1n1zzWkskUEd0f5jPIUis33p+v
# kY8szduAtCcIcPFUhI8Hb5alPUAPMjGzwKb7NIKbnf8j8cP18As5IveckF0oh1cw
# 63RY/vPK62LDYdpi7WnG2ObvngfWVKtwiwTI4jHj2cO9q37HDe/PPl216gSpUZh0
# ap24mKmMDfcKp1N4mEdsxz4oseOrPYeFsHHWJFJ6Aivvqn70KTeJpp5r+DxSqbeS
# y0mxIUOq/lAaUxgNSQVUX26t8r+fcikofKv23WHrtRV3t7rVTsB9YzrRaiikmz68
# K5HWdt9MqULxPQPo+ppZ0LRqkOae466+UKRY0JxWtdrMc5vHlHZfnqjawj/RsM2S
# 6Q6fa9T9CnY1Nz7DYBG3yZJyCPFsrgU05s9ljqfsSptpFdUh9R4ce+L71SWDLM2x
# /1MFLLHAMbXsEp8KloEGtaDULnxtfS2tYhfuKGqRXoEfDPAMnIdTvQPh3GHQ4Sjk
# kBARHL0MY75alhGTKHWjC2aLVOo8obKIBk8hfnFDUf/EyVw4uTCCB3EwggVZoAMC
# AQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29m
# dCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIy
# NVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9
# DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2
# Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N
# 7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXc
# ag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJ
# j361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjk
# lqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37Zy
# L9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M
# 269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLX
# pyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLU
# HMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode
# 2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEA
# ATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYE
# FJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEB
# MEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMv
# RG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEE
# AYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB
# /zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEug
# SaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9N
# aWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsG
# AQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jv
# b0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt
# 4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsP
# MeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++
# Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9
# QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2
# wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aR
# AfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5z
# bcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nx
# t67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3
# Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+AN
# uOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/Z
# cGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLUMIICPQIBATCCAQChgdikgdUw
# gdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsT
# JE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMd
# VGhhbGVzIFRTUyBFU046M0JENC00QjgwLTY5QzMxJTAjBgNVBAMTHE1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVACGlCa3ketyeuey7
# bJNpWkMuiCcQoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAw
# DQYJKoZIhvcNAQEFBQACBQDl8JbeMCIYDzIwMjIwNDAxMDUwODQ2WhgPMjAyMjA0
# MDIwNTA4NDZaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAOXwlt4CAQAwBwIBAAIC
# HrUwBwIBAAICEXowCgIFAOXx6F4CAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYB
# BAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOB
# gQBynpnXFrRApEsCkyTqXx/tnE7Fr1e+kUhqFw5oIluoEILtB7kX39GlOSBFJ/mp
# i6RtBOowCPhMS7rV5vrT16PoKu8C8e5MWpTknY35g36BCsh/zKkA9ohIwtfYB8Fl
# hIn1xIkyYTdcPIkKDZF9Qzy7vcB7wnlkPjxCk6zmfZoWnDGCBA0wggQJAgEBMIGT
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABibS/hjCEHEuPAAEA
# AAGJMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQ
# AQQwLwYJKoZIhvcNAQkEMSIEIDuG29DPq+hOQk2K9EjrNY+ZH0b+LiGjjuX1Sa09
# uMjAMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgZndHMdxQV1VsbpWHOTHq
# WEycvcRJm7cY69l/UmT8j0UwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAYm0v4YwhBxLjwABAAABiTAiBCDSHBeTYsKt9mK6n/EKOBeu
# ekvuFEidCH9yQudtFzVyrzANBgkqhkiG9w0BAQsFAASCAgAgL1foPrlmRK0Rr/zx
# fEgnAcLlLyisMxz07pIG+rXggs3jEgoNRDmFReACd9IU5turGy14EHu8RzJGaAWs
# icnjkPXAfEzRn3Cu+f62GX3f9tP3U9RNLY3BhCTE8+CypAONYHftD4R17aXGnyeX
# 1dKY1dmeLEeRlmpguhOXgxfzJwPiQbOCd0/Bkljr681r8Nox0ns9lHruFrxLazw+
# wnETK/9yOK/J8Z+gicmclDmPmbevechMxhzMJ8MN39Tnw4A266Hxi8xjLqQTxI3x
# w9QrZmU8gc+RR+3KEDrjny+k8Fnlld3WojEfLLwBV7W9MNsB2FWsdri6kKMmY22p
# CYdXtI2yKIwd6kuAPrv56/2/nE49vIAVL1V7vGU2OIt2IaYuisy5jkjEs4a0OjCw
# ycKs0OG7HfHbzl6ZcOrN575u4IJIwteK6FZl6QRhzeWtcxcz2zbcxrA7HB2d6Hdf
# TQHD++q/Yt+J0fZ56R5kpW22yZz0yk7FUJGL2Zrj3dyZR5IYG97U9HiOroGyd/oG
# bLUdEKK+UYPjBEOv+ZAi0LcZw6nEW2DDqfo7Q48dI052AyZbwYyU3nMxjB9Ywngy
# wkuAgvebjfwfIvL76XK0rKYa9srXiQNMhHFNQxHB8vLB4X0XU3pL8zUUc+SocRkU
# VnU8SLmOX2Pi6m/I5S5ORWILSw==
# SIG # End signature block