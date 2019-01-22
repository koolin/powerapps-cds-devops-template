param(
    [Parameter(Mandatory=$true)]
    [string]$UniqueName,
    [Parameter(Mandatory=$true)]
    [string]$OrgName,
    [Parameter(Mandatory=$true)]
    [string]$Region,
    [Parameter(Mandatory=$true)]
    [string]$UserName,
    [Parameter(Mandatory=$true)]
    [string]$Password
)

$connParams = @{
    OrganizationName = $UniqueName 
    ServerUrl = "https://$OrgName.$Region.dynamics.com"
    Credential = [PSCredential]::new($UserName, ($Password | ConvertTo-SecureString -AsPlainText -Force))
}

Write-Verbose $connParams

.\Execute-DeleteDataFromJson.ps1 -CrmConnectionParameters $connParams -Verbose -RecordDirectory /deletes/