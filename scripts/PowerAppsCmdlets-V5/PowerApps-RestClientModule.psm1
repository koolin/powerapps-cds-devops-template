$local:ErrorActionPreference = "Stop"

Import-Module "$(Split-Path $script:MyInvocation.MyCommand.Path)\PowerApps-AuthModule.psm1" -Force

function Get-AudienceForHostName
{
    [CmdletBinding()]
    Param(
        [string] $Uri
    )

    $hostMapping = @{
        "management.azure.com" = "https://management.azure.com/";
        "api.powerapps.com" = "https://service.powerapps.com/";
        "tip1.api.powerapps.com" = "https://service.powerapps.com/";
        "tip2.api.powerapps.com" = "https://service.powerapps.com/";
        "graph.windows.net" = "https://graph.windows.net/";
        "api.bap.microsoft.com" = "https://service.powerapps.com/";
        "tip1.api.bap.microsoft.com" = "https://service.powerapps.com/";
        "tip2.api.bap.microsoft.com" = "https://service.powerapps.com/";
        "api.flow.microsoft.com" = "https://service.flow.microsoft.com/";
        "tip1.api.flow.microsoft.com" = "https://service.flow.microsoft.com/";
        "tip2.api.flow.microsoft.com" = "https://service.flow.microsoft.com/";
    }

    $uriObject = New-Object System.Uri($Uri)
    $host = $uriObject.Host

    if ($hostMapping[$host] -ne $null)
    {
        return $hostMapping[$host];
    }

    Write-Verbose "Unknown host $host. Using https://management.azure.com/ as a default";
    return "https://management.azure.com/";
}

function Invoke-Request(
    [CmdletBinding()]

    [Parameter(Mandatory=$True)]
    [string] $Uri,

    [Parameter(Mandatory=$True)]
    [string] $Method,

    [object] $Body = $null,

    [Hashtable] $Headers = @{},

    [switch] $ParseContent,

    [switch] $ThrowOnFailure
)
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    
    $audience = Get-AudienceForHostName -Uri $Uri
    $token = Get-JwtToken -Audience $audience
    $Headers["Authorization"] = "Bearer $token";
    $Headers["User-Agent"] = "PowerShell cmdlets 1.0";

    try {
        if ($Body -eq $null -or $Body -eq "")
        {
            $response = Invoke-WebRequest -Uri $Uri -Headers $Headers -Method $Method -UseBasicParsing
        }
        else 
        {
            $jsonBody = ConvertTo-Json $Body -Depth 20
            $response = Invoke-WebRequest -Uri $Uri -Headers $Headers -Method $Method -ContentType "application/json" -Body $jsonBody -UseBasicParsing
        }

        if ($ParseContent)
        {
            if ($response.Content)
            {
                return ConvertFrom-Json $response.Content;
            }
        }

        return $response
    } catch {
        $response = $_.Exception.Response
        if ($_.ErrorDetails)
        {
            $errorResponse = ConvertFrom-Json $_.ErrorDetails;
            $code = $response.StatusCode
            $message = $errorResponse.Error.Message
            Write-Verbose "Status Code: '$code'. Message: '$message'" 
        }

        if ($ThrowOnFailure)
        {
            throw;
        }
        else 
        {
            return $response
        }
    }
}


function InvokeApi
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Route,

        [Parameter(Mandatory = $false)]
        [object]$Body = $null,

        [Parameter(Mandatory = $false)]
        [switch]$ThrowOnFailure,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2016-11-01"
    )
    
    Test-PowerAppsAccount;

    $uri = $Route `
        | ReplaceMacro -Macro "{apiVersion}"  -Value $ApiVersion `
        | ReplaceMacro -Macro "{flowEndpoint}" -Value $global:currentSession.flowEndpoint `
        | ReplaceMacro -Macro "{powerAppsEndpoint}" -Value $global:currentSession.powerAppsEndpoint `
        | ReplaceMacro -Macro "{bapEndpoint}" -Value $global:currentSession.bapEndpoint `
        | ReplaceMacro -Macro "{graphEndpoint}" -Value $global:currentSession.graphEndpoint `
        | ReplaceMacro -Macro "{cdsOneEndpoint}" -Value $global:currentSession.cdsOneEndpoint;

    Write-Verbose $uri

    If($ThrowOnFailure)
    {    
        $result = Invoke-Request `
        -Uri $uri `
        -Method $Method `
        -Body $body `
        -ParseContent `
        -ThrowOnFailure;
    }
    else {
        $result = Invoke-Request `
        -Uri $uri `
        -Method $Method `
        -Body $body `
        -ParseContent;        
    }

    if($result.nextLink)
    {
        $nextLink = $result.nextLink
        $resultValue = $result.value

        while($nextLink) 
        {
            If($ThrowOnFailure)
            {    
                $nextResult = Invoke-Request `
                -Uri $nextLinkuri `
                -Method $Method `
                -Body $body `
                -ParseContent `
                -ThrowOnFailure;
            }
            else {
                $nextResult = Invoke-Request `
                -Uri $nextLink `
                -Method $Method `
                -Body $body `
                -ParseContent;        
            }
    
            $nextLink = $nextResult.nextLink    
            $resultValue = $resultValue + $nextResult.value
        }

        return New-Object -TypeName PSObject `
            | Add-Member -PassThru -MemberType NoteProperty -Name value -Value $resultValue `
    }

    return $result;
}

function InvokeApiNoParseContent
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Route,

        [Parameter(Mandatory = $false)]
        [object]$Body = $null,

        [Parameter(Mandatory = $false)]
        [switch]$ThrowOnFailure,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2016-11-01"
    )
    
    Test-PowerAppsAccount;

    $uri = $Route `
        | ReplaceMacro -Macro "{apiVersion}"  -Value $ApiVersion `
        | ReplaceMacro -Macro "{flowEndpoint}" -Value $global:currentSession.flowEndpoint `
        | ReplaceMacro -Macro "{powerAppsEndpoint}" -Value $global:currentSession.powerAppsEndpoint `
        | ReplaceMacro -Macro "{bapEndpoint}" -Value $global:currentSession.bapEndpoint `
        | ReplaceMacro -Macro "{graphEndpoint}" -Value $global:currentSession.graphEndpoint `
        | ReplaceMacro -Macro "{cdsOneEndpoint}" -Value $global:currentSession.cdsOneEndpoint;

    Write-Verbose $uri

    If($ThrowOnFailure)
    {    
        $result = Invoke-Request `
        -Uri $uri `
        -Method $Method `
        -Body $body `
        -ThrowOnFailure;
    }
    else {
        $result = Invoke-Request `
        -Uri $uri `
        -Method $Method `
        -Body $body `
    }

    if($result.nextLink)
    {
        $nextLink = $result.nextLink
        $resultValue = $result.value

        while($nextLink) 
        {
            If($ThrowOnFailure)
            {    
                $nextResult = Invoke-Request `
                -Uri $nextLinkuri `
                -Method $Method `
                -Body $body `
                -ThrowOnFailure;
            }
            else {
                $nextResult = Invoke-Request `
                -Uri $nextLink `
                -Method $Method `
                -Body $body `;
            }
    
            $nextLink = $nextResult.nextLink    
            $resultValue = $resultValue + $nextResult.value
        }

        return New-Object -TypeName PSObject `
            | Add-Member -PassThru -MemberType NoteProperty -Name value -Value $resultValue `
    }

    return $result;
}

function ReplaceMacro
{
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Input,

        [Parameter(Mandatory = $true)]
        [string]$Macro,

        [Parameter(Mandatory = $false)]
        [string]$Value
    )

    return $Input.Replace($Macro, $Value)
}


function BuildFilterPattern
{
    param
    (
        [Parameter(Mandatory = $false)]
        [object]$Filter
    )

    if ($Filter -eq $null -or $Filter.Length -eq 0)
    {
        return New-Object System.Management.Automation.WildcardPattern "*"
    }
    else
    {
        return New-Object System.Management.Automation.WildcardPattern @($Filter,"IgnoreCase")
    }
}


function ResolveEnvironment
{
    param
    (
        [Parameter(Mandatory = $false)]
        [string]$OverrideId
    )

    if (-not [string]::IsNullOrWhiteSpace($OverrideId))
    {
        return $OverrideId;
    }
    elseif ($global:currentSession.selectedEnvironment)
    {
        return $global:currentSession.selectedEnvironment;
    }
    
    return "~default";
}


function Select-CurrentEnvironment
{
 <#
 .SYNOPSIS
 Sets the current environment for listing powerapps, flows, and other environment resources
 .DESCRIPTION
 The Select-CurrentEnvironment cmdlet sets the current environment in which commands will
 execute when an environment is not specified. Use Get-Help Select-CurrentEnvironment -Examples 
 for more detail.
 .PARAMETER EnvironmentName
 Environment identifier (not display name).
 .PARAMETER Default
 Shortcut to specify the default tenant environment
 .EXAMPLE
 Select-CurrentEnvironment -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 Select environment 3c2f7648-ad60-4871-91cb-b77d7ef3c239 as the current environment. Cmdlets invoked
 after running this command will operate against this environment.
 .EXAMPLE
 Select-CurrentEnvironment ~default
 Select the default environment. Cmdlets invoked after running this will operate against the default
 environment. 
 #>
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName=$true, ParameterSetName = "Name")]
        [String]$EnvironmentName,

        [Parameter(Mandatory = $true, ParameterSetName = "Default")]
        [Switch]$Default
    )

    Test-PowerAppsAccount;

    if ($Default)
    {
        $global:currentSession.selectedEnvironment = "~default";
    }
    else
    {
        $global:currentSession.selectedEnvironment = $EnvironmentName;
    }
}
# SIG # Begin signature block
# MIInpwYJKoZIhvcNAQcCoIInmDCCJ5QCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAlk3+LbfgRAuyX
# +3QWDCpNC4jOtNyZApKo1eAzYT/MDKCCEWQwggh2MIIHXqADAgECAhM2AAAAh2rh
# X7Bvfrt0AAEAAACHMA0GCSqGSIb3DQEBCwUAMEExEzARBgoJkiaJk/IsZAEZFgNH
# QkwxEzARBgoJkiaJk/IsZAEZFgNBTUUxFTATBgNVBAMTDEFNRSBDUyBDQSAwMTAe
# Fw0xODA3MTAxMzA4NDlaFw0xOTA3MTAxMzA4NDlaMC8xLTArBgNVBAMTJE1pY3Jv
# c29mdCBBenVyZSBEZXBlbmRlbmN5IENvZGUgU2lnbjCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAPf3/ZREq1xrUwIv3rE+B+9hgWu6A+9pATQBXADzJ1qA
# hxEKwDgBnpI3w4my/XssamM1SXZ1Ly/RqiAhbBnWiu57Mak5zIctiVAoH+JIliQD
# 2F8CO+K1drdj+V+MouJnlhYFYw5zEjJxk8gQVXBj+VlEcIVPBd+FBpuhAfWGHC/8
# NZYS779+HrCG1i5qGBpVEFK0Yx9shdJ3wBVWD0L4ZziltKV3oOdjysJ8rL8iL/Ig
# DcIlmcb4BnL0th/MAJLUTBxWRyUxKYyolabZIExXia3DmNz2EFmKpix7URu7eVQM
# SgAMXtUdWmaX5vJPYEXFBszAwI2Kq3cs85EJSFUWJB8CAwEAAaOCBXcwggVzMCkG
# CSsGAQQBgjcVCgQcMBowDAYKKwYBBAGCN1sDATAKBggrBgEFBQcDAzA8BgkrBgEE
# AYI3FQcELzAtBiUrBgEEAYI3FQiGkOMNhNW0eITxiz6Fm90Wzp0SgWDigi2HkK4D
# AgFkAgENMIICdgYIKwYBBQUHAQEEggJoMIICZDBiBggrBgEFBQcwAoZWaHR0cDov
# L2NybC5taWNyb3NvZnQuY29tL3BraWluZnJhL0NlcnRzL0JZMlBLSUNTQ0EwMS5B
# TUUuR0JMX0FNRSUyMENTJTIwQ0ElMjAwMSgxKS5jcnQwUgYIKwYBBQUHMAKGRmh0
# dHA6Ly9jcmwxLmFtZS5nYmwvYWlhL0JZMlBLSUNTQ0EwMS5BTUUuR0JMX0FNRSUy
# MENTJTIwQ0ElMjAwMSgxKS5jcnQwUgYIKwYBBQUHMAKGRmh0dHA6Ly9jcmwyLmFt
# ZS5nYmwvYWlhL0JZMlBLSUNTQ0EwMS5BTUUuR0JMX0FNRSUyMENTJTIwQ0ElMjAw
# MSgxKS5jcnQwUgYIKwYBBQUHMAKGRmh0dHA6Ly9jcmwzLmFtZS5nYmwvYWlhL0JZ
# MlBLSUNTQ0EwMS5BTUUuR0JMX0FNRSUyMENTJTIwQ0ElMjAwMSgxKS5jcnQwUgYI
# KwYBBQUHMAKGRmh0dHA6Ly9jcmw0LmFtZS5nYmwvYWlhL0JZMlBLSUNTQ0EwMS5B
# TUUuR0JMX0FNRSUyMENTJTIwQ0ElMjAwMSgxKS5jcnQwga0GCCsGAQUFBzAChoGg
# bGRhcDovLy9DTj1BTUUlMjBDUyUyMENBJTIwMDEsQ049QUlBLENOPVB1YmxpYyUy
# MEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9
# QU1FLERDPUdCTD9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlm
# aWNhdGlvbkF1dGhvcml0eTAdBgNVHQ4EFgQULZktR9nSbfs0Ys9sqwYAWWCZPxsw
# DgYDVR0PAQH/BAQDAgeAMEUGA1UdEQQ+MDykOjA4MR4wHAYDVQQLExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xFjAUBgNVBAUTDTIzNjE2OSs0MzgwNDcwggHUBgNVHR8E
# ggHLMIIBxzCCAcOgggG/oIIBu4Y8aHR0cDovL2NybC5taWNyb3NvZnQuY29tL3Br
# aWluZnJhL0NSTC9BTUUlMjBDUyUyMENBJTIwMDEuY3Jshi5odHRwOi8vY3JsMS5h
# bWUuZ2JsL2NybC9BTUUlMjBDUyUyMENBJTIwMDEuY3Jshi5odHRwOi8vY3JsMi5h
# bWUuZ2JsL2NybC9BTUUlMjBDUyUyMENBJTIwMDEuY3Jshi5odHRwOi8vY3JsMy5h
# bWUuZ2JsL2NybC9BTUUlMjBDUyUyMENBJTIwMDEuY3Jshi5odHRwOi8vY3JsNC5h
# bWUuZ2JsL2NybC9BTUUlMjBDUyUyMENBJTIwMDEuY3JshoG6bGRhcDovLy9DTj1B
# TUUlMjBDUyUyMENBJTIwMDEsQ049QlkyUEtJQ1NDQTAxLENOPUNEUCxDTj1QdWJs
# aWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9u
# LERDPUFNRSxEQz1HQkw/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29i
# amVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MB8GA1UdIwQYMBaAFBtmohn8
# m+ul2oSPGJjpEKTDe5K9MB8GA1UdJQQYMBYGCisGAQQBgjdbAwEGCCsGAQUFBwMD
# MA0GCSqGSIb3DQEBCwUAA4IBAQDPWYN9t5RNknehD6HG/lGEJokcOcgxiCw5kMen
# fHjsQzVonpYznweZUGuy/yvR4FqCKejkJe38NFLB156IeV2RZwl8J5BBeM093b8c
# b4fWdPmAOixP43wFSKy4WHJKcpohSHCT/g5+nfwUP6/BYx0fqGKoISbJW6fyJ9NI
# gTBYkJ9g2awJg3dLRvRXeV53WONNBu1KrgJ9Ne6Yo1fKUI6VBUmS5fL3B0VbkUn1
# JdeP1H0exAV+Qk3mkfC0r28APVQ49i1gcc+rFaWc76bRZyj1lfBXZP3UVbLN6iDF
# G7NHSzlh15r4TgAuf8zKQklUhE30ZQc+24DFcoK0Gar3JX7IMIII5jCCBs6gAwIB
# AgITHwAAABS0xR/G8oC+cQAAAAAAFDANBgkqhkiG9w0BAQsFADA8MRMwEQYKCZIm
# iZPyLGQBGRYDR0JMMRMwEQYKCZImiZPyLGQBGRYDQU1FMRAwDgYDVQQDEwdhbWVy
# b290MB4XDTE2MDkxNTIxMzMwM1oXDTIxMDkxNTIxNDMwM1owQTETMBEGCgmSJomT
# 8ixkARkWA0dCTDETMBEGCgmSJomT8ixkARkWA0FNRTEVMBMGA1UEAxMMQU1FIENT
# IENBIDAxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1VeBAtb5+tD3
# G4C53TfNJNxmYfzhiXKtKQzSGxuav660bTS1VEeDDjSnFhsmnlb6GkPCeYmCJwWg
# ZGs+3oWJ8yad3//VoP99bXG8azzTJmT2PFM1yKxUXUJgi7I9y3C4ll/ATfBwbGGR
# XD+2PdkdlVpxKWzeNEPVwbCtxWjUhHr6Ecy9R6O23j+2/RSZSgfzYctDzDWhNf0P
# vGPflm31PSk4+ozca337/Ozu0+naDKg5i/zFHhfSJZkq5dPPG6C8wDrdiwHh6G5I
# GrMd2QXnmvEfjtpPqE+G8MeWbszaWxlxEjQJQC6PBwn+8Qt4Vqlc0am3Z3fBw8kz
# RunOs8Mn/wIDAQABo4IE2jCCBNYwEAYJKwYBBAGCNxUBBAMCAQEwIwYJKwYBBAGC
# NxUCBBYEFJH8M85CnvaT5uJ9VNcIGLu413FlMB0GA1UdDgQWBBQbZqIZ/JvrpdqE
# jxiY6RCkw3uSvTCCAQQGA1UdJQSB/DCB+QYHKwYBBQIDBQYIKwYBBQUHAwEGCCsG
# AQUFBwMCBgorBgEEAYI3FAIBBgkrBgEEAYI3FQYGCisGAQQBgjcKAwwGCSsGAQQB
# gjcVBgYIKwYBBQUHAwkGCCsGAQUFCAICBgorBgEEAYI3QAEBBgsrBgEEAYI3CgME
# AQYKKwYBBAGCNwoDBAYJKwYBBAGCNxUFBgorBgEEAYI3FAICBgorBgEEAYI3FAID
# BggrBgEFBQcDAwYKKwYBBAGCN1sBAQYKKwYBBAGCN1sCAQYKKwYBBAGCN1sDAQYK
# KwYBBAGCN1sFAQYKKwYBBAGCN1sEAQYKKwYBBAGCN1sEAjAZBgkrBgEEAYI3FAIE
# DB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADAf
# BgNVHSMEGDAWgBQpXlFeZK40ueusnA2njHUB0QkLKDCCAWgGA1UdHwSCAV8wggFb
# MIIBV6CCAVOgggFPhiNodHRwOi8vY3JsMS5hbWUuZ2JsL2NybC9hbWVyb290LmNy
# bIYxaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraWluZnJhL2NybC9hbWVyb290
# LmNybIYjaHR0cDovL2NybDIuYW1lLmdibC9jcmwvYW1lcm9vdC5jcmyGI2h0dHA6
# Ly9jcmwzLmFtZS5nYmwvY3JsL2FtZXJvb3QuY3JshoGqbGRhcDovLy9DTj1hbWVy
# b290LENOPUFNRVJPT1QsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2Vz
# LENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9QU1FLERDPUdCTD9jZXJ0
# aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJp
# YnV0aW9uUG9pbnQwggGrBggrBgEFBQcBAQSCAZ0wggGZMDcGCCsGAQUFBzAChito
# dHRwOi8vY3JsMS5hbWUuZ2JsL2FpYS9BTUVST09UX2FtZXJvb3QuY3J0MEcGCCsG
# AQUFBzAChjtodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpaW5mcmEvY2VydHMv
# QU1FUk9PVF9hbWVyb290LmNydDA3BggrBgEFBQcwAoYraHR0cDovL2NybDIuYW1l
# LmdibC9haWEvQU1FUk9PVF9hbWVyb290LmNydDA3BggrBgEFBQcwAoYraHR0cDov
# L2NybDMuYW1lLmdibC9haWEvQU1FUk9PVF9hbWVyb290LmNydDCBogYIKwYBBQUH
# MAKGgZVsZGFwOi8vL0NOPWFtZXJvb3QsQ049QUlBLENOPVB1YmxpYyUyMEtleSUy
# MFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9QU1FLERD
# PUdCTD9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlv
# bkF1dGhvcml0eTANBgkqhkiG9w0BAQsFAAOCAgEAKLdKhpqPH6QBaM3CAOqQi8oA
# 4WQeZLW3QOXNmWm7UA018DQEa1yTqEQbuD5OlR1Wu/F289DmXNTdsZM4GTKEaZeh
# IiVaMoLvEJtu5h6CTyfWqPetNyOJqR1sGqod0Xwn5/G/zcTYSxn5K3N8KdlcDrZA
# Iyfq3yaEJYHGnA9eJ/f1RrfbJgeo/RAhICctOONwfpsBXcgiTuTmlD/k0DqogvzJ
# gPq9GOkIyX/dxk7IkPzX/n484s0zHR4IKU58U3G1oPSQmZ5OHAvgHaEASkdN5E20
# HyJv5zN7du+QY08fI+VIci6pagLfXHYaTX3ZJ/MUM9XU+oU5y4qMLzTj1JIG0LVf
# uHK8yoB7h2inyTe7bn6h2G8NxZ02aKZ0xa+n/JnoXKNsaVPG1SoTuItMsXV5pQtI
# ShsBqnXqFjY3bJMlMhIofMcjiuOwRCW+prZ+PoYvE2P+ML7gs3L65GZ9BdKF3fSW
# 3TvmpOujPQ23rzSle9WGxFJ02fNbaF9C7bG44uDzMoZU4P+uvQaB7KE4OMqAvYYf
# Fy1tv1dpVIN/qhx0H/9oNiOJpuZZ39ZibLt9DXbsq5qwyHmdJXaisxwB53wJshUj
# c1i76xqFPUNGb8EZQ3aFKl2w9B47vfBi+nU3sN0tpnLPtew4LHWq4LBD5uiNZVBO
# YosZ6BKhSlk1+Y/0y1IxghWZMIIVlQIBATBYMEExEzARBgoJkiaJk/IsZAEZFgNH
# QkwxEzARBgoJkiaJk/IsZAEZFgNBTUUxFTATBgNVBAMTDEFNRSBDUyBDQSAwMQIT
# NgAAAIdq4V+wb367dAABAAAAhzANBglghkgBZQMEAgEFAKCBxjAZBgkqhkiG9w0B
# CQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAv
# BgkqhkiG9w0BCQQxIgQgfYfL+8OkIp3ZFHck/k085gG2NYEv+ihnrJDPLPXJ6OUw
# WgYKKwYBBAGCNwIBDDFMMEqgLIAqAE0AaQBjAHIAbwBzAG8AZgB0ACAAQwBvAHIA
# cABvAHIAYQB0AGkAbwBuoRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTANBgkq
# hkiG9w0BAQEFAASCAQAc6/iL93YbGTuIhegUKRZNN/6psMPasY9zH6S/IYZk2/rx
# J8UNIKKdPz/uY09fhDcgAmlSuQ0zH+vNr5QUzNJSO3bjzpO4LSAz5UnfmO9/SLCB
# Qpb7SFrp9JXy7Kj3cfZCVm63oeqwAwTgStp3TWXXoa4JFnSazxvKigotY36TFCCw
# BY+lhGeuyq3+NK6zXHdJwvp+A/Zw1xsWLACfEdhz/s3ovyMzN6aJS4Mc0i70SKtW
# eDJw4Br0CRLeVipz96xPlCikw2teOaZoGDIrWLpEmED/TQ1WsXa1mLGfpc+nPx7B
# GV5cScJBgMHbB9T09/4OfMA1/GY1IiFprByl/AxvoYITSTCCE0UGCisGAQQBgjcD
# AwExghM1MIITMQYJKoZIhvcNAQcCoIITIjCCEx4CAQMxDzANBglghkgBZQMEAgEF
# ADCCATwGCyqGSIb3DQEJEAEEoIIBKwSCAScwggEjAgEBBgorBgEEAYRZCgMBMDEw
# DQYJYIZIAWUDBAIBBQAEIGcWaAKkF7ci3GwrsKquffWlZR8fV+MxVv+ihhtIrzSj
# AgZbfFM8KYEYEzIwMTgwODIzMTUwNTE4LjA5NlowBwIBAYACAfSggbikgbUwgbIx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xDDAKBgNVBAsTA0FP
# QzEnMCUGA1UECxMebkNpcGhlciBEU0UgRVNOOkQyMzYtMzdEQS05NzYxMSUwIwYD
# VQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIOzTCCBnEwggRZoAMC
# AQICCmEJgSoAAAAAAAIwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENl
# cnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTEwMDcwMTIxMzY1NVoXDTI1MDcw
# MTIxNDY1NVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggEiMA0GCSqG
# SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCpHQ28dxGKOiDs/BOX9fp/aZRrdFQQ1aUK
# AIKF++18aEssX8XD5WHCdrc+Zitb8BVTJwQxH0EbGpUdzgkTjnxhMFmxMEQP8WCI
# hFRDDNdNuDgIs0Ldk6zWczBXJoKjRQ3Q6vVHgc2/JGAyWGBG8lhHhjKEHnRhZ5Ff
# gVSxz5NMksHEpl3RYRNuKMYa+YaAu99h/EbBJx0kZxJyGiGKr0tkiVBisV39dx89
# 8Fd1rL2KQk1AUdEPnAY+Z3/1ZsADlkR+79BL/W7lmsqxqPJ6Kgox8NpOBpG2iAg1
# 6HgcsOmZzTznL0S6p/TcZL2kAcEgCZN4zfy8wMlEXV4WnAEFTyJNAgMBAAGjggHm
# MIIB4jAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU1WM6XIoxkPNDe3xGG8Uz
# aFqFbVUwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8G
# A1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQw
# VgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9j
# cmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUF
# BwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwgaAGA1UdIAEB/wSB
# lTCBkjCBjwYJKwYBBAGCNy4DMIGBMD0GCCsGAQUFBwIBFjFodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vUEtJL2RvY3MvQ1BTL2RlZmF1bHQuaHRtMEAGCCsGAQUFBwIC
# MDQeMiAdAEwAZQBnAGEAbABfAFAAbwBsAGkAYwB5AF8AUwB0AGEAdABlAG0AZQBu
# AHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQAH5ohRDeLG4Jg/gXEDPZ2joSFvs+um
# zPUxvs8F4qn++ldtGTCzwsVmyWrf9efweL3HqJ4l4/m87WtUVwgrUYJEEvu5U4zM
# 9GASinbMQEBBm9xcF/9c+V4XNZgkVkt070IQyK+/f8Z/8jd9Wj8c8pl5SpFSAK84
# Dxf1L3mBZdmptWvkx872ynoAb0swRCQiPM/tA6WWj1kpvLb9BOFwnzJKJ/1Vry/+
# tuWOM7tiX5rbV0Dp8c6ZZpCM/2pif93FSguRJuI57BlKcWOdeyFtw5yjojz6f32W
# apB4pm3S4Zz5Hfw42JT0xqUKloakvZ4argRCg7i1gJsiOCC1JeVk7Pf0v35jWSUP
# ei45V3aicaoGig+JFrphpxHLmtgOR5qAxdDNp9DvfYPw4TtxCd9ddJgiCGHasFAe
# b73x4QDf5zEHpJM692VHeOj4qEir995yfmFrb3epgcunCaw5u+zGy9iCtHLNHfS4
# hQEegPsbiSpUObJb2sgNVZl6h3M7COaYLeqN4DMuEin1wC9UJyH3yKxO2ii4sanb
# lrKnQqLJzxlBTeCG+SqaoxFmMNO7dDJL32N79ZmKLxvHIa9Zta7cRDyXUHHXodLF
# VeNp3lfB0d4wwP3M5k37Db9dT+mdHhk4L7zPWAUu7w2gUDXa7wknHNWzfjUeCLra
# NtvTX4/edIhJEjCCBNkwggPBoAMCAQICEzMAAACuDtZOlonbAPUAAAAAAK4wDQYJ
# KoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMTYw
# OTA3MTc1NjU1WhcNMTgwOTA3MTc1NjU1WjCBsjELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEMMAoGA1UECxMDQU9DMScwJQYDVQQLEx5uQ2lwaGVy
# IERTRSBFU046RDIzNi0zN0RBLTk3NjExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFNlcnZpY2UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDe
# ki/DpJVy9T4NZmTD+uboIg90jE3Bnse2VLjxj059H/tGML58y3ue28RnWJIv+lSA
# Bp+jPp8XIf2p//DKYb0o/QSOJ8kGUoFYesNTPtqyf/qohLW1rcLijiFoMLABH/GD
# nDbgRZHxVFxHUG+KNwffdC0BYC3Vfq3+2uOO8czRlj10gRHU2BK8moSz53Vo2ZwF
# 3TMZyVgvAvlg5sarNgRwAYwbwWW5wEqpeODFX1VA/nAeLkjirCmg875M1XiEyPtr
# XDAFLng5/y5MlAcUMYJ6dHuSBDqLLXipjjYakQopB3H1+9s8iyDoBM07JqP9u55V
# P5a2n/IZFNNwJHeCTSvLAgMBAAGjggEbMIIBFzAdBgNVHQ4EFgQUfo/lNDREi/J5
# QLjGoNGcQx4hJbEwHwYDVR0jBBgwFoAU1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYD
# VR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwv
# cHJvZHVjdHMvTWljVGltU3RhUENBXzIwMTAtMDctMDEuY3JsMFoGCCsGAQUFBwEB
# BE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9j
# ZXJ0cy9NaWNUaW1TdGFQQ0FfMjAxMC0wNy0wMS5jcnQwDAYDVR0TAQH/BAIwADAT
# BgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG9w0BAQsFAAOCAQEAPVlNePD0XDQI
# 0bVBYANTDPmMpk3lIh6gPIilg0hKQpZNMADLbmj+kav0GZcxtWnwrBoR+fpBsuao
# wWgwxExCHBo6mix7RLeJvNyNYlCk2JQT/Ga80SRVzOAL5Nxls1PqvDbgFghDcRTm
# pZMvADfqwdu5R6FNyIgecYNoyb7A4AqCLfV1Wx3PrPyaXbatskk5mT8NqWLYLshB
# zt2Ca0bhJJZf6qQwg6r2gz1pG15ue6nDq/mjYpTmCDhYz46b8rxrIn0sQxnFTmtn
# tvz2Z1jCGs99n1rr2ZFrGXOJS4Bhn1tyKEFwGJjrfQ4Gb2pyA9aKRwUyK9BHLKWC
# 5ZLD0hAaIKGCA3cwggJfAgEBMIHioYG4pIG1MIGyMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMQwwCgYDVQQLEwNBT0MxJzAlBgNVBAsTHm5DaXBo
# ZXIgRFNFIEVTTjpEMjM2LTM3REEtOTc2MTElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgU2VydmljZaIlCgEBMAkGBSsOAwIaBQADFQDHwb0we6UYnmReZ3Q2
# +rvjmbxo+6CBwTCBvqSBuzCBuDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEMMAoGA1UECxMDQU9DMScwJQYDVQQLEx5uQ2lwaGVyIE5UUyBFU046
# MjY2NS00QzNGLUM1REUxKzApBgNVBAMTIk1pY3Jvc29mdCBUaW1lIFNvdXJjZSBN
# YXN0ZXIgQ2xvY2swDQYJKoZIhvcNAQEFBQACBQDfKP8dMCIYDzIwMTgwODIzMDkz
# ODM3WhgPMjAxODA4MjQwOTM4MzdaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAN8o
# /x0CAQAwCgIBAAICAIgCAf8wBwIBAAICGSMwCgIFAN8qUJ0CAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAaAKMAgCAQACAxbjYKEKMAgCAQACAx6EgDAN
# BgkqhkiG9w0BAQUFAAOCAQEAdXPHlYuzbzeKtYBhLgIJpR9Yn/OtcQihsq/v/DhU
# Vf6dwEXtCv8Ai9QnLHIbtJlATM7nJOuVNj2I9xk9yoM1GviH/4LWng/nNHCBWlqU
# yJYIZ0UjP6dRH8e/UelR3ds6tJonl2BQAx3KZMhLUfVF5pt6WpHDRDugrEkZS3bp
# qVBvBWehqdgkctnlLBKU9S74QydX2BQ7NeSX7zHd4h40jrago8ZdJtOxlXLYRA0c
# z3rfN6y9IphPZ1S481IHnm+iE0njG9pR5h2IIE84iX47p+sT88M77/qCncE8clQU
# LPzmgk2+btrTrYWvQ3e/Z2QsLJidiWhCdz7Yy3n8vCwE3jGCAvUwggLxAgEBMIGT
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAArg7WTpaJ2wD1AAAA
# AACuMA0GCWCGSAFlAwQCAQUAoIIBMjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQ
# AQQwLwYJKoZIhvcNAQkEMSIEIKVwh8ZYtdVJiK7tNK6wCiEGKcTM4/6Zaxxik1gq
# HePTMIHiBgsqhkiG9w0BCRACDDGB0jCBzzCBzDCBsQQUx8G9MHulGJ5kXmd0Nvq7
# 45m8aPswgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# AK4O1k6WidsA9QAAAAAArjAWBBQGEdFNi7+MobAmmTAYfAHe/wu8pjANBgkqhkiG
# 9w0BAQsFAASCAQC3hs2kbgTsYWAAanDAR7VBWNj/h41vzFOokowd6jVi1uR8FEs1
# +OH9M9eEXbbw6+nIN24t1pONx3Yn40bJgC/8Oc1+zXxiuGx1jOhjpNwGNTW9YI4V
# hTwvYEAqS3pdsSvl0/3ipS2XIyZVuCuYgFCE/jwvGSAARHNGllQECOb/k0FEWb+X
# t3wUv+bfSbQo0ATCT6PlQjH8Ej3SDQuBwr0n1qfy0yPBcuRbQBqR1B5vzhBZ3LOF
# HtAJ4vl3gY45qpjsaoE7lEPCJg6t4Pz5XCeEGY2Ux7jCWON6PuDP+DbiF9loq6CG
# yGQtYm5w/TybXF43w5SCUZcLt2pSfHNH4DFi
# SIG # End signature block
