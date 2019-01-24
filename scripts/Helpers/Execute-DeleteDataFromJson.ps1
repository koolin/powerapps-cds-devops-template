param(
    
    [Parameter(ParameterSetName='CrmConnectionNameSet')]	
    [ValidateSet('Online','OnPremise','InternetFacingDeployment','Online-Prod')]
    [string]
    $CrmConnectionName, # e.g. 'Online-Dev',

    [Parameter(Mandatory,ParameterSetName='CrmConnectionParametersSet')]
    [ValidateNotNullOrEmpty()]
    [hashtable]
    $CrmConnectionParameters,

    [string]
    $RecordDirectory = "/temp/deletes/"
)


if($CrmConnectionName) {
    $CrmConnectionParameters = & "$PSScriptRoot\..\CrmConnectionParameters\$CrmConnectionName.ps1"
}

if (-not(Get-Module -Name Microsoft.Xrm.Data.PowerShell)) {
    Import-Module Microsoft.Xrm.Data.PowerShell
}

$crmConnection = Connect-CrmOnline -Credential $CrmConnectionParameters.Credential -ServerUrl $CrmConnectionParameters.ServerUrl

Write-Verbose $crmConnection

$Directory = "$PSScriptRoot/$RecordDirectory"

Write-Verbose "Record Directory: $Directory"

# get listing of json files in delete directory location
$recordFiles = Get-ChildItem -Path $Directory -Filter '*.json'

Write-Verbose "Returned $recordFiles.Count .json files in directory."

foreach($recordFile in $recordFiles) {
    # get content of JSON file
    $recordData = (Get-Content -Path $recordFile.FullName -Encoding UTF8) | ConvertFrom-Json

    foreach($record in $recordData) {
        try {
            $resultRecord = $crmConnection.Retrieve($record.logicalname, $record.id, [Microsoft.Xrm.Sdk.Query.ColumnSet]::new($false))
            Write-Host "Deleting $record"
            try {
                $crmConnection.Delete($record.logicalname,  $record.id)
                Write-Verbose "Deleting $record succeeded."
            }
            catch {
                Write-Error "Deleting $record failed."
            }
        }
        catch {
            Write-Warning "$record not found"
        }
    }
}

