param (
    [string]
    $EnvironmentDisplayName,

    [string]
    $EnvironmentName,

    [switch]
    $UseDisplayNameMatch,

    [switch]
    $RemoveOnly,

    [switch]
    $BypassConfirm,

    [string]
    [ValidateSet("unitedstates","europe","asia","australia","india","japan","canada","unitedkingdom","unitedstatesfirstrelease","southamerica")]
    $LocationName = "canada",

    [ValidateSet("Trial","Production")]
    [string]
    $EnvironmentSku = "Trial",

    [string]
    $CurrencyName = "USD",

    [string]
    $LanguageName = "1033",

    [int]
    $SleepSeconds = 30

)

$environmentRegions = @{
    unitedstates = "crm"
    europe = "crm4"
    asia = "crm5"
    australia = "crm6"
    india = "crm8"
    japan = "crm7"
    canada = "crm3"
    unitedkingdom = "crm11"
    unitedstatesfirstrelease = "crm0"
    southamerica = "crm2"
}

if (-not(Get-Module -Name Microsoft.PowerApps.Administration.PowerShell) -or -not(Get-Module -Name Microsoft.PowerApps.PowerShell)) {
    Write-Host "Importing PowerApp Admin Modules..."
    Install-Module -Name Microsoft.PowerApps.Administration.PowerShell -Force -AllowClobber
    Install-Module -Name Microsoft.PowerApps.PowerShell -Force -AllowClobber
}

dir . | Unblock-File

Write-Host "Initializing PowerApps Account..."

# set PowerApps account
Add-PowerAppsAccount

# get all environments and select item to remove
$cdsEnvironmentList = Get-PowerAppEnvironment

if ($EnvironmentName) {
    $cdsEnvironment = $cdsEnvironmentList | where EnvironmentName -EQ $EnvironmentName
} elseif ($EnvironmentDisplayName) {
    if ($UseDisplayNameMatch) {
        $cdsEnvironment = $cdsEnvironmentList | where DisplayName -Match $EnvironmentDisplayName
    } else {
        $cdsEnvironment = $cdsEnvironmentList | where DisplayName -EQ $EnvironmentDisplayName
    }
} else {
    Write-Output "No environment selected from parameters, listing environments..."

    Write-Output "0. [Create New Environment] `n"
    for ($a=0; $a -lt $cdsEnvironmentList.Length; $a++){
        Write-Output "$($a + 1): $($cdsEnvironmentList[$a].DisplayName) ($($cdsEnvironmentList[$a].EnvironmentName))"
    }

    do {
        try {
            $selectOk = $true
            [int]$value = Read-host "Please select an environment"
        }
        catch {
            $selectOk = $false
        }
    } until (($value -ge 0 -and $value -lt $cdsEnvironmentList.Length + 1) -and $selectOK)

    if ($value -ne 0) {
        $cdsEnvironment = $cdsEnvironmentList[$value - 1]
    }
}

if ($cdsEnvironment) {
    Write-Output "Environment Selected: $($cdsEnvironment.DisplayName) ($($cdsEnvironment.EnvironmentName))"

    if (-not $BypassConfirm) {
        [string]$value = Read-host "Please confirm environment (Y)? "
        if ( -not ($value -eq "Y") -or -not ($value -eq "y")) {
            Write-Warning "CDS Environment not confirmed"
            Return
        }
    }    
    
    Write-Output "Initializing remove environment..."
    $removeEnvironmentResult = Remove-AdminPowerAppEnvironment -EnvironmentName $cdsEnvironment.EnvironmentName

    if ($removeEnvironmentResult.Code -eq 202 -and $removeEnvironmentResult.Description -eq "Accepted") {
        Write-Output "Remove environment submitted, sleeping waiting for delete..."
    } elseif ($removeEnvironmentResult.Errors) {
        Write-Warning "Environment removal error: $($removeEnvironmentResult.Internal.errors)"
        Return
    }

    # ensure the environment is removed before continuing
    do {
        Start-Sleep -Seconds $sleepSeconds
        $cdsEnvironmentList = Get-PowerAppEnvironment
        $removeEnvironment = $cdsEnvironmentList | where EnvironmentName -EQ $cdsEnvironment.EnvironmentName
    } While ($removeEnvironment)

    Write-Output "Environment Deleted."

    #check for org domain name
    $orgIndex = $cdsEnvironment.DisplayName.IndexOf("(")
    if ($orgIndex -ge 1) {
        # get old display name without domain in brackets
        $EnvironmentDisplayName = $cdsEnvironment.DisplayName.Substring(0, $orgIndex).Trim()
    } else {
        $EnvironmentDisplayName = $cdsEnvironment.DisplayName
    }
} else {
    [string]$EnvironmentDisplayName = Read-host "No existing environment. Please enter a display name for new environment"
}

if ($RemoveOnly) {
    Return
}

try {
    # create new environment
    Write-Output "Creating new environment..."
    $newEnvironment = New-AdminPowerAppEnvironment -DisplayName $EnvironmentDisplayName -LocationName $LocationName -EnvironmentSku $EnvironmentSku

    # create database for new environment
    Write-Output "Creating database for $($newEnvironment.DisplayName)..."
    $newEnvironmentDb = New-AdminPowerAppCdsDatabase -EnvironmentName $newEnvironment.EnvironmentName -CurrencyName $CurrencyName -LanguageName $LanguageName
    Write-Output "Environment Reset:$($newEnvironment.DisplayName) - Completed"
}
catch {
    Write-Warning "Unabled to create new environment: $($_.Exception.Message)"
    Return
}

Write-Output $newEnvironmentDb

$domainName = $newEnvironmentDb.DisplayName.Substring($newEnvironmentDb.DisplayName.IndexOf("(")+1).Trim(")")

Write-Output "Domain Name: $($domainName)"

$environmentUri = "https://$($domainName).$($environmentRegions[$newEnvironmentDb.Location]).dynamics.com"

Write-Output "URI: $environmentUri"