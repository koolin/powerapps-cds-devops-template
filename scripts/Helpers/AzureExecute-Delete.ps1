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

Write-Verbose "Username: $UserName"
Write-Verbose "Password: $Password"

$connParams = @{
    OrganizationName = $UniqueName 
    ServerUrl = "https://$OrgName.$Region.dynamics.com"
    Credential = [PSCredential]::new($UserName, ($Password | ConvertTo-SecureString -AsPlainText -Force))
}

$connParams

$connParams.Credential

#.\Helpers\Execute-DeleteDataFromJson.ps1 -CrmConnectionParameters $connParams -Verbose -RecordDirectory /deletes/