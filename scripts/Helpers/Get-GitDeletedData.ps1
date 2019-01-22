param(
    [Parameter(Mandatory=$True)]
    [string]
    $Source, # e.g. '368c014f',

    [Parameter(Mandatory=$True)]
    [string]
    $Target, # e.g. '099f1a38',

    [string]
    $Pattern = '/.+/(?<type>[\w_]+)/records/(?<id>[0-9a-f\-]+)\.xml$',

    [string]
    $DataDirectory = "/crm/data/",

    [string]
    $RecordDirectory = "/temp/deletes/"
)

$FullDataDirectory = "$PSScriptRoot/../..$DataDirectory"

# set to directory for git execution
Set-Location $FullDataDirectory

# get deleted files between commits
$deletedFiles = git diff $Source $Target --summary --diff-filter=D --no-renames

# set back to script root
Set-Location $PSScriptRoot

$recordedRecords = @()

$deletedFiles | % {
    # assert line matches expected format
    $match = [Regex]::Match($_, '(?<=^ delete mode 100644 ).+$')
    if ($match.Success) {
        Write-Verbose "Line: $match"
        # check if path matches the specified pattern
        $partsMatch = [Regex]::Match($match, $Pattern)
        if ($partsMatch.Success) {
            Write-Verbose "Line matches pattern."
            # get parts (named groups)
            $typeGroup = $partsMatch.Groups | Where-Object { $_.Name -eq 'type' } | Select-Object -First 1
            $idGroup = $partsMatch.Groups | Where-Object { $_.Name -eq 'id' } | Select-Object -First 1
            if ($typeGroup -and $idGroup) {
                $hash = @{            
                    id = [guid]$idGroup.Value                
                    logicalname = $typeGroup.Value
                }
                $fileObject = New-Object PSObject -Property $hash
                Write-Verbose ($fileObject | Out-String)
                $recordedRecords += $fileObject
            } else {
                Write-Error "Type and/or ID not found. Source: $match"
            }
        }
        else {
            Write-Verbose "Line does not match pattern."
        }
    }
    else {
        Write-Error "Failed to interpret line. Source: `"$_`""
    }
}

Write-Verbose "Record Directory: $RecordDirectory"
if(-not (Test-Path -Path $RecordDirectory)) {
    md -Force $RecordDirectory
    Write-Verbose "Created directory: $RecordDirectory"
}

# check for recorded files
if ($recordedRecords.Count -gt 0 -and $RecordDirectory) {
    # create random json file name and create path
    $recordFileName = [guid]::NewGuid().ToString() + ".json"
    $FullRecordDirectory = "$RecordDirectory$recordFileName"
    Write-Verbose "Record Directory File Path: $FullRecordDirectory"
    
    # write records to json file
    $recordedRecords | ConvertTo-Json | Out-File $FullRecordDirectory -Force

    Write-Output "Deleted files have been recorded as entity records and saved as $recordFileName"
    Write-Verbose $FullRecordDirectory
}
else {
	Write-Output "No deleted files were recorded."
}