param(
    
    [Parameter(Mandatory,ParameterSetName='CrmConnectionNameSet')]	
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

$crmConnection = Microsoft.Xrm.Tooling.CrmConnector.Powershell\Get-CrmConnection @CrmConnectionParameters

$Directory = "$PSScriptRoot/../..$RecordDirectory"

# get listing of json files in delete directory location
$recordFiles = Get-ChildItem -Path $Directory -Filter '*.json'

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

