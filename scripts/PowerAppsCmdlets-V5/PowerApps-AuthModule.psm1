$local:ErrorActionPreference = "Stop"

[Reflection.Assembly]::LoadFile("$(Split-Path $script:MyInvocation.MyCommand.Path)\Microsoft.IdentityModel.Clients.ActiveDirectory.dll") | Out-Null
[Reflection.Assembly]::LoadFile("$(Split-Path $script:MyInvocation.MyCommand.Path)\Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll") | Out-Null

function Get-JwtTokenClaims
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$JwtToken
    )

    $tokenSplit = $JwtToken.Split(".")
    $claimsSegment = $tokenSplit[1].Replace(" ", "+");
    
    $mod = $claimsSegment.Length % 4
    if ($mod -gt 0)
    {
        $paddingCount = 4 - $mod;
        for ($i = 0; $i -lt $paddingCount; $i++)
        {
            $claimsSegment += "="
        }
    }

    $decodedClaimsSegment = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($claimsSegment))

    return ConvertFrom-Json $decodedClaimsSegment
}

function Add-PowerAppsAccount
{
    [CmdletBinding()]
    param
    (
        [string] $Audience = "https://management.azure.com/",

        [Parameter(Mandatory = $false)]
        [ValidateSet("prod","preview","tip1", "tip2")]
        [string]$Endpoint = "prod",

        [string]$Username = $null,

        [SecureString]$Password = $null
    )
    
    $authContext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext("https://login.windows.net/common");
    $redirectUri = New-Object System.Uri("urn:ietf:wg:oauth:2.0:oob");

    if ($Username -ne $null -and $Password -ne $null)
    {
        $credential = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.UserCredential($Username, $Password)
        $authResult = $authContext.AcquireToken($Audience, "1950a258-227b-4e31-a9cf-717495945fc2", $credential);
    }
    else {
        $authResult = $authContext.AcquireToken($Audience, "1950a258-227b-4e31-a9cf-717495945fc2", $redirectUri, 1);
    }

    $claims = Get-JwtTokenClaims -JwtToken $authResult.IdToken

    $global:currentSession = @{
        loggedIn = $true;
        idToken = $authResult.IdToken;
        upn = $claims.upn;
        tenantId = $claims.tid;
        userId = $claims.oid;
        refreshToken = $authResult.RefreshToken;
        expiresOn = (Get-Date).AddHours(8);
        resourceTokens = @{
            $Audience = @{
                accessToken = $authResult.AccessToken;
                expiresOn = $authResult.ExpiresOn;
            }
        };
        selectedEnvironment = "~default";
        flowEndpoint = 
            switch ($Endpoint)
            {
                "prod"      { "api.flow.microsoft.com" }
                "preview"   { "preview.api.flow.microsoft.com" }
                "tip1"      { "tip1.api.flow.microsoft.com"}
                "tip2"      { "tip2.api.flow.microsoft.com" }
                default     { throw "Unsupported endpoint '$Endpoint'"}
            };
        powerAppsEndpoint = 
            switch ($Endpoint)
            {
                "prod"      { "api.powerapps.com" }
                "preview"   { "preview.api.powerapps.com" }
                "tip1"      { "tip1.api.powerapps.com"}
                "tip2"      { "tip2.api.powerapps.com" }
                default     { throw "Unsupported endpoint '$Endpoint'"}
            };            
        bapEndpoint = 
            switch ($Endpoint)
            {
                "prod"      { "api.bap.microsoft.com" }
                "preview"   { "preview.api.bap.microsoft.com" }
                "tip1"      { "tip1.api.bap.microsoft.com"}
                "tip2"      { "tip2.api.bap.microsoft.com" }
                default     { throw "Unsupported endpoint '$Endpoint'"}
            };      
        graphEndpoint = 
            switch ($Endpoint)
            {
                "prod"      { "graph.windows.net" }
                "preview"   { "graph.windows.net" }
                "tip1"      { "graph.windows.net"}
                "tip2"      { "graph.windows.net" }
                default     { throw "Unsupported endpoint '$Endpoint'"}
            };
        cdsOneEndpoint = 
            switch ($Endpoint)
            {
                "prod"      { "api.cds.microsoft.com" }
                "preview"   { "preview.api.cds.microsoft.com" }
                "tip1"      { "tip1.api.cds.microsoft.com"}
                "tip2"      { "tip2.api.cds.microsoft.com" }
                default     { throw "Unsupported endpoint '$Endpoint'"}
            };
    };
}

function Test-PowerAppsAccount
{
    [CmdletBinding()]
    param
    (
    )

    if (-not $global:currentSession)
    {
        Add-PowerAppsAccount
    }
}

function Remove-PowerAppsAccount
{
    [CmdletBinding()]
    param
    (
    )

    if ($global:currentSession -ne $null -and $global:currentSession.upn -ne $null)
    {
        Write-Verbose "Logging out $($global:currentSession.upn)"
    }
    else
    {
        Write-Verbose "No user logged in"
    }

    $global:currentSession = @{
        loggedIn = $false;
    };
}

function Get-JwtToken
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string] $Audience
    )

    if ($global:currentSession -eq $null)
    {
        $global:currentSession = @{
            loggedIn = $false;
        };
    }

    if ($global:currentSession.loggedIn -eq $false -or $global:currentSession.expiresOn -lt (Get-Date))
    {
        Write-Verbose "No user logged in. Signing the user in before acquiring token."
        Add-PowerAppsAccount -Audience $Audience
    }

    if ($global:currentSession.resourceTokens[$Audience] -eq $null -or `
        $global:currentSession.resourceTokens[$Audience].accessToken -eq $null -or `
        $global:currentSession.resourceTokens[$Audience].expiresOn -eq $null -or `
        $global:currentSession.resourceTokens[$Audience].expiresOn -lt (Get-Date))
    {

        Write-Verbose "Token for $Audience is either missing or expired. Acquiring a new one."

        $tenantId = $global:currentSession.tenantId
        $authContext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext("https://login.windows.net/$tenantId");
        $refreshTokenResult = $authContext.AcquireTokenByRefreshToken($global:currentSession.refreshToken, "1950a258-227b-4e31-a9cf-717495945fc2", $Audience)
        $global:currentSession.resourceTokens[$Audience] = @{
            accessToken = $refreshTokenResult.AccessToken;
            expiresOn = $refreshTokenResult.ExpiresOn;
        }
    }

    return $global:currentSession.resourceTokens[$Audience].accessToken;
}

function Invoke-OAuthDialog
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string] $ConsentLinkUri
    )

    Add-Type -AssemblyName System.Windows.Forms
    $form = New-Object -TypeName System.Windows.Forms.Form -Property @{ Width=440; Height=640 }
    $web  = New-Object -TypeName System.Windows.Forms.WebBrowser -Property @{ Width=420; Height=600; Url=$ConsentLinkUri }
    $DocComp  = {
        $Global:uri = $web.Url.AbsoluteUri        
        if ($Global:uri -match "error=[^&]*|code=[^&]*")
        {
            $form.Close()
        }
    }
    $web.ScriptErrorsSuppressed = $true
    $web.Add_DocumentCompleted($DocComp)
    $form.Controls.Add($web)
    $form.Add_Shown({$form.Activate()})
    $form.ShowDialog() | Out-Null
    $queryOutput = [System.Web.HttpUtility]::ParseQueryString($web.Url.Query)

    $output = @{}

    foreach($key in $queryOutput.Keys)
    {
        $output["$key"] = $queryOutput[$key]
    }
    
    return $output
}


function Get-TenantDetailsFromGraph
{
 <#
 .SYNOPSIS
 .
 .DESCRIPTION
 The Get-TenantDetailsFromGraph function . 
 Use Get-Help Get-TenantDetailsFromGraph -Examples for more detail.
 .EXAMPLE
 Get-TenantDetailsFromGraph
 .
 #>
    param
    (
        [string]$GraphApiVersion = "1.6"
    )

    process 
    {
        $TenantIdentifier = "myorganization"

        $route = "https://{graphEndpoint}/{tenantIdentifier}/tenantDetails`?api-version={graphApiVersion}" `
        | ReplaceMacro -Macro "{tenantIdentifier}" -Value $TenantIdentifier `
        | ReplaceMacro -Macro "{graphApiVersion}" -Value $GraphApiVersion;

        $graphResponse = InvokeApi -Method GET -Route $route
        
        CreateTenantObject -TenantObj $graphResponse.value

    }
}

#Returns users or groups from Graph
#wrapper on top of https://msdn.microsoft.com/en-us/library/azure/ad/graph/api/users-operations & https://msdn.microsoft.com/en-us/library/azure/ad/graph/api/groups-operations 
function Get-UsersOrGroupsFromGraph(
)
{
    [CmdletBinding(DefaultParameterSetName="Id")]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "Id")]
        [string]$ObjectId,

        [Parameter(Mandatory = $true, ParameterSetName = "Search")]
        [string]$SearchString,

        [Parameter(Mandatory = $false, ParameterSetName = "Search")]
        [Parameter(Mandatory = $false, ParameterSetName = "Id")]
        [string]$GraphApiVersion = "1.6"
    )

    Process
    {
        if (-not [string]::IsNullOrWhiteSpace($ObjectId))
        {
            $userGraphUri = "https://graph.windows.net/myorganization/users/{userId}`?&api-version={graphApiVersion}" `
            | ReplaceMacro -Macro "{userId}" -Value $ObjectId `
            | ReplaceMacro -Macro "{graphApiVersion}" -Value $GraphApiVersion;

            $userGraphResponse = InvokeApi -Route $userGraphUri -Method GET
            
            If($userGraphResponse.StatusCode -eq $null)
            {
                CreateUserObject -UserObj $userGraphResponse
            }

            $groupsGraphUri = "https://graph.windows.net/myorganization/groups/{groupId}`?api-version={graphApiVersion}" `
            | ReplaceMacro -Macro "{groupId}" -Value $ObjectId `
            | ReplaceMacro -Macro "{graphApiVersion}" -Value $GraphApiVersion;

            $groupGraphResponse = InvokeApi -Route $groupsGraphUri -Method GET

            If($groupGraphResponse.StatusCode -eq $null)
            {
                CreateGroupObject -GroupObj $groupGraphResponse
            }
        }
        else 
        {
            $userFilter = "startswith(userPrincipalName,'$SearchString') or startswith(displayName,'$SearchString')"
    
            $userGraphUri = "https://graph.windows.net/myorganization/users`?`$filter={filter}&api-version={graphApiVersion}" `
            | ReplaceMacro -Macro "{filter}" -Value $userFilter `
            | ReplaceMacro -Macro "{graphApiVersion}" -Value $GraphApiVersion;

            $userGraphResponse = InvokeApi -Route $userGraphUri -Method GET
    
            foreach($user in $userGraphResponse.value)
            {
                CreateUserObject -UserObj $user
            }

            $groupFilter = "startswith(displayName,'$SearchString')"
    
            $groupsGraphUri = "https://graph.windows.net/myorganization/groups`?`$filter={filter}&api-version={graphApiVersion}" `
            | ReplaceMacro -Macro "{filter}" -Value $groupFilter `
            | ReplaceMacro -Macro "{graphApiVersion}" -Value $GraphApiVersion;

            $groupsGraphResponse = Invoke-Request -Uri $groupsGraphUri -Method GET -ParseContent -ThrowOnFailure
    
            foreach($group in $groupsGraphResponse.value)
            {
                CreateGroupObject -GroupObj $group
            }    
        }
    }
}


function CreateUserObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$UserObj
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name ObjectType -Value $UserObj.objectType `
        | Add-Member -PassThru -MemberType NoteProperty -Name ObjectId -Value $UserObj.objectId `
        | Add-Member -PassThru -MemberType NoteProperty -Name UserPrincipalName -Value $UserObj.userPrincipalName `
        | Add-Member -PassThru -MemberType NoteProperty -Name Mail -Value $UserObj.mail `
        | Add-Member -PassThru -MemberType NoteProperty -Name DisplayName -Value $UserObj.displayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name AssignedLicenses -Value $UserObj.assignedLicenses `
        | Add-Member -PassThru -MemberType NoteProperty -Name AssignedPlans -Value $UserObj.assignedLicenses `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $UserObj;
}

function CreateGroupObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$GroupObj
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name ObjectType -Value $GroupObj.objectType `
        | Add-Member -PassThru -MemberType NoteProperty -Name Objectd -Value $GroupObj.objectId `
        | Add-Member -PassThru -MemberType NoteProperty -Name Mail -Value $GroupObj.mail `
        | Add-Member -PassThru -MemberType NoteProperty -Name DisplayName -Value $GroupObj.displayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $GroupObj;
}


function CreateTenantObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$TenantObj
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name ObjectType -Value $TenantObj.objectType `
        | Add-Member -PassThru -MemberType NoteProperty -Name TenantId -Value $TenantObj.objectId `
        | Add-Member -PassThru -MemberType NoteProperty -Name Country -Value $TenantObj.countryLetterCode `
        | Add-Member -PassThru -MemberType NoteProperty -Name Language -Value $TenantObj.preferredLanguage `
        | Add-Member -PassThru -MemberType NoteProperty -Name DisplayName -Value $TenantObj.displayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name Domains -Value $TenantObj.verifiedDomains `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $TenantObj;
}

# SIG # Begin signature block
# MIInpwYJKoZIhvcNAQcCoIInmDCCJ5QCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAgPgYb2Z1Mpeha
# erDJpuqOastcCIOwFBs3VlpkdDrY7qCCEWQwggh2MIIHXqADAgECAhM2AAAAh2rh
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
# BgkqhkiG9w0BCQQxIgQg9ZOuZu7N2Lt2eoHm0XSgXRAeSpD0yy9Dxoh26p9t22Iw
# WgYKKwYBBAGCNwIBDDFMMEqgLIAqAE0AaQBjAHIAbwBzAG8AZgB0ACAAQwBvAHIA
# cABvAHIAYQB0AGkAbwBuoRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTANBgkq
# hkiG9w0BAQEFAASCAQBF4bjJMTWbp3nyr6txMjTksPsYYh5nSPLFf43cKclXLhuM
# 0G9xMVw6PXLUMEB9Bs1VVqxD0bUb6HHkrwbzHOe1gmQgqT8t6NJK4fD44mQT96s6
# B8zzKXvSsIt3h+jS2m2YGpEeEwgT+DtDtb4YbHGA3yGYhNEjAO1vMNgcQQptEZoo
# V6nGEu7MZPIaQgUbP3/qp1pdpIHDWodKml63pTmc3LshfJ6vEVX5mMxO1k0QTtiV
# siySRfGXJvyLfe/GaFwE0apuPAWiKE8OLsua7PhJEwCKwMJfB8SstPdu+LsA1AS0
# wYLHWax7bAZyTrZaC6zB8IPLtWU+UjbwjaViBad6oYITSTCCE0UGCisGAQQBgjcD
# AwExghM1MIITMQYJKoZIhvcNAQcCoIITIjCCEx4CAQMxDzANBglghkgBZQMEAgEF
# ADCCATwGCyqGSIb3DQEJEAEEoIIBKwSCAScwggEjAgEBBgorBgEEAYRZCgMBMDEw
# DQYJYIZIAWUDBAIBBQAEINw/jiRoAET/M9EI623c51oJVqZLnsuuZ0QuDopAm6zJ
# AgZbfEziEMcYEzIwMTgwODIzMTUwNTAyLjY5NFowBwIBAYACAfSggbikgbUwgbIx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xDDAKBgNVBAsTA0FP
# QzEnMCUGA1UECxMebkNpcGhlciBEU0UgRVNOOjEyRTctMzA2NC02MTEyMSUwIwYD
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
# NtvTX4/edIhJEjCCBNkwggPBoAMCAQICEzMAAACsiiG8etKbcvQAAAAAAKwwDQYJ
# KoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMTYw
# OTA3MTc1NjU0WhcNMTgwOTA3MTc1NjU0WjCBsjELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEMMAoGA1UECxMDQU9DMScwJQYDVQQLEx5uQ2lwaGVy
# IERTRSBFU046MTJFNy0zMDY0LTYxMTIxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFNlcnZpY2UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCh
# xPQ8pY5zMaEXQVyrdwi3qdFDqrvf3HT5ujVWaoQJ2Km7+1T3GNnGpbND6PomAcw9
# NfV+C+RMmCrThpUlBVzeuzsNL2Lsj9mMdK83ixebazenSrA0rXLIifWBzKHVP6jz
# sQWo96cHukHZqI8xRp3tYivgapt5LLrn9Rm2Jn+E0h2lKDOw5sIteZiriOMPH2Z7
# mtgYXmyB8ThgdB46p6frNGpcXr11pa1Vkldl0iY6oBAKQQSxJ5Bn4N7ui5Wj5wDk
# DZzGAg6n1ptMPTPJhL2uosW84YjnSp/2suNap3qOjKEYXmpGzvasq5qyqPyvfqfk
# sOfNBaJntfpC8dIDJKrnAgMBAAGjggEbMIIBFzAdBgNVHQ4EFgQU2EdwqIU1ixNh
# r4eQ6EUXJOCYpw0wHwYDVR0jBBgwFoAU1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYD
# VR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwv
# cHJvZHVjdHMvTWljVGltU3RhUENBXzIwMTAtMDctMDEuY3JsMFoGCCsGAQUFBwEB
# BE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9j
# ZXJ0cy9NaWNUaW1TdGFQQ0FfMjAxMC0wNy0wMS5jcnQwDAYDVR0TAQH/BAIwADAT
# BgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG9w0BAQsFAAOCAQEASOzoXifDGxic
# XbTOdm43DB9dYxwNXaQj0hW0ztBACeWbX6zxee1w7TJeXQx1IfTz1BWJAfVla7HA
# 1oxa0LiF/Uf6rfRvEEmGmHr9wWEbr3xiErllTFE2V/mdYBSEwdj74m8QLBeFY37C
# jx4TFe+AB/FQly3kvfrJKDaYYTTXTAFYAKpi0AcDTcESXZcshJ/O8UZs9fr0BgrO
# m5h7qeQ1CJNmDMVEqElQt/cFO3dxqrAKv3Fu/nsT5GkABu+vIibgxX6tNmqccIIX
# KALgv7zDIaRAAWtXV9LwnmstDUbIp8dH/oSVm3tPnCPlrB3+C28vPnvJdbtJi/yO
# uETd+rLn+qGCA3cwggJfAgEBMIHioYG4pIG1MIGyMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMQwwCgYDVQQLEwNBT0MxJzAlBgNVBAsTHm5DaXBo
# ZXIgRFNFIEVTTjoxMkU3LTMwNjQtNjExMjElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgU2VydmljZaIlCgEBMAkGBSsOAwIaBQADFQA5cCWLFMh53V8MXemL
# nLOUmfcct6CBwTCBvqSBuzCBuDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEMMAoGA1UECxMDQU9DMScwJQYDVQQLEx5uQ2lwaGVyIE5UUyBFU046
# MjY2NS00QzNGLUM1REUxKzApBgNVBAMTIk1pY3Jvc29mdCBUaW1lIFNvdXJjZSBN
# YXN0ZXIgQ2xvY2swDQYJKoZIhvcNAQEFBQACBQDfKP4PMCIYDzIwMTgwODIzMDkz
# NDA3WhgPMjAxODA4MjQwOTM0MDdaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAN8o
# /g8CAQAwCgIBAAICIxACAf8wBwIBAAICGNMwCgIFAN8qT48CAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAaAKMAgCAQACAxbjYKEKMAgCAQACAwehIDAN
# BgkqhkiG9w0BAQUFAAOCAQEAFlRVdOUpmUK2Pu/c0Jk0/A0ypLBN+VRXdOYzND+C
# zkPE2e01hHJZ0LMUow4hYr0Us5SwuYzi0TGnOvIksR3Go1d+HIB4HvUuclLOeA+D
# Fqqr6Z4tqnr80Ba0zKT4MR5aIlO0wClbXGJp14h6dJkq6J/JUFR+xi1YQisPLmx8
# 970mYbwdC+4YKrvcDfVnT8zhBhIUR4q9SYbzWgPvOFK1kHrw5w1m0cojqw5C9JKU
# NT2KvdMMK5sC1CwuTM88WuZTKKZxJlUdobIf1Fkh48Wk/F9Yh3nla3wKDvH97Wv8
# ofY84yzCg7jtlNf0bOMj0roYkUqohMzVz7iwsU8MrU9KrjGCAvUwggLxAgEBMIGT
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAArIohvHrSm3L0AAAA
# AACsMA0GCWCGSAFlAwQCAQUAoIIBMjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQ
# AQQwLwYJKoZIhvcNAQkEMSIEIEmfRnyYttSEHDUkA1MOqlSoCaKgr+lRu4aqtGDD
# JgS0MIHiBgsqhkiG9w0BCRACDDGB0jCBzzCBzDCBsQQUOXAlixTIed1fDF3pi5yz
# lJn3HLcwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# AKyKIbx60pty9AAAAAAArDAWBBSV9+iTP3tEodHoVWuJfM9j1lPyGjANBgkqhkiG
# 9w0BAQsFAASCAQA/cuKvRO1QXLxLXKSPy6iFggXpAfmwAgiFEe7qZpyL0l9K5IO8
# kTgMqbYfzKHNgF1GEXh/hdZkMs/SBS7rHpzDT30oONlZPbQ+UQmMbj3ONP10qQy4
# r7oiQis1jQ/fx8EeeqEHfIwO8O9l8cEnPgMvTGbdt0aML6iJMIDg2CvH/HKehnlI
# nymqlADOzBLv//BtUH38+icLiU80jFSIrV5zyJAH5PIZImem4iioH7tXXOVZ93Jk
# LW81IwPCxY0C6zZJ9VpN76y0X9tKDUsayguqKxcU0CFM46NlCUpqnaAVexKRYFVm
# 7zu9Sb0oWOj68tmUbd0BPsZJRpx5ckH9uE8g
# SIG # End signature block
