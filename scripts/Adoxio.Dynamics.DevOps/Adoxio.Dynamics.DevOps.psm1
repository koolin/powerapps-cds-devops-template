Set-StrictMode -Version Latest

function GetSolutionPackagerFolder {
    if(Test-Path "$env:CRM_SDK_PATH\Bin\SolutionPackager.exe") { # CRM 8.x SDK)
        return "$env:CRM_SDK_PATH\Bin"
    } elseif(Test-Path "$env:CRM_SDK_PATH\CoreTools\SolutionPackager.exe") { # CRM 9.x SDK
        return "$env:CRM_SDK_PATH\CoreTools"
    } else {
        throw "SolutionPackager.exe could not be found. Verify the CRM_SDK_PATH environment variable has been set to the 'SDK' folder for CRM 8.x SDK, or the 'Tools' folder for CRM 9.x SDK."
    }
}

function GetPackageDeployerFolder {
    if(Test-Path "$env:CRM_SDK_PATH\Tools\PackageDeployer\PackageDeployer.exe") { # CRM 8.x SDK)
        return "$env:CRM_SDK_PATH\Tools\PackageDeployer"
    } elseif(Test-Path "$env:CRM_SDK_PATH\PackageDeployment\PackageDeployer.exe") { # CRM 9.x SDK
        return "$env:CRM_SDK_PATH\PackageDeployment"
    } else {
        throw "PackageDeployer.exe could not be found. Verify the CRM_SDK_PATH environment variable has been set to the 'SDK' folder for CRM 8.x SDK, or the 'Tools' folder for CRM 9.x SDK."
    }
}

<#
.Synopsis
   Packages an unpacked CRM solution folder using the SolutionPackager tool.
.DESCRIPTION
   This function packs an unpacked CRM solution folder and its individual components using the SolutionPackager tool included in the Dynamics 365 SDK. The SolutionPackager documentation is located online at https://msdn.microsoft.com/en-us/library/jj602987.aspx.
.EXAMPLE
   Compress-CrmSolution -Folder 'C:\temp\solutions\AdventureWorks' -ZipFile 'C:\temp\packed\AdventureWorks.zip' -PackageType Unmanaged

   This example packs the AdventureWorks unmananged solution to a zip file.
.EXAMPLE
   Compress-CrmSolution -Folder 'C:\temp\solutions\AdventureWorks' -MappingXmlFile 'C:\temp\solutions\AdventureWorks.mapping.xml' -ZipFile 'C:\temp\packed\AdventureWorks.zip' -PackageType Unmanaged

   This example packs the AdventureWorks unmanaged solution to a zip file and uses an XML mapping file as used by the /map parameter of the SolutionPackager tool.
.EXAMPLE
   Compress-CrmSolution -Folder 'C:\temp\solutions\AdventureWorks' -ZipFile 'C:\temp\export\AdventureWorks.zip' -PackageType Managed

   This example packs the AdventureWorks managed solution to a zip file using the SolutionPackager tool. The managed version of solution must exist in the same folder as the unmanaged solution and end with the name _managed.zip (e.g. AdventureWorks_managed.zip).
#>
function Compress-CrmSolution {
    [CmdletBinding()]
    param (
        # The folder path to an unpacked solution. See the /folder parameter of the SolutionPackager tool.
        [Parameter(Mandatory, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Folder,

        # The path and name of an .xml file containing file mapping directives. See the /map parameter of the SolutionPackager tool.
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$MappingXmlFile,

        # The package type to process. See the /packagetype parameter of the SolutionPackager tool.
        [Parameter(Mandatory, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("Unmanaged","Managed")]
        [string]$PackageType,

        # The target solution zip file to create. See the /zipfile parameter of the SolutionPackager tool.
        [Parameter(Mandatory, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ZipFile
    )
    process
    {
        $solutionPackagerArgs = "/nologo",
                                "/action:Pack",
                                "/folder:$Folder",
                                "/packagetype:$PackageType",
                                "/zipfile:$ZipFile"

        if($MappingXmlFile) {
            $solutionPackagerArgs += "/map:$MappingXmlFile"
        }

        # extract the solutions
        & "$(GetSolutionPackagerFolder)\SolutionPackager.exe" $solutionPackagerArgs
    }
}

<#
.Synopsis
   Extracts a CRM solution zip file using the SolutionPackager tool.
.DESCRIPTION
   This function extracts a CRM solution file to its individual components using the SolutionPackager tool included in the Dynamics 365 SDK. The SolutionPackager documentation is located online at https://msdn.microsoft.com/en-us/library/jj602987.aspx.
.EXAMPLE
   Expand-CrmSolution -ZipFile 'C:\temp\export\AdventureWorks.zip' -PackageType Unmanaged -Folder 'C:\temp\solutions\AdventureWorks'

   This example extracts the AdventureWorks solution to a folder.
.EXAMPLE
   Expand-CrmSolution -ZipFile 'C:\temp\export\AdventureWorks.zip' -MappingXmlFile 'C:\temp\solutions\AdventureWorks.mapping.xml' -PackageType Unmanaged -Folder 'C:\temp\solutions\AdventureWorks'

   This example extracts the AdventureWorks solution to a folder and uses an XML mapping file as used by the /map parameter of the SolutionPackager tool.
.EXAMPLE
   Expand-CrmSolution -ZipFile 'C:\temp\export\AdventureWorks.zip' -PackageType Both -Folder 'C:\temp\solutions\AdventureWorks'

   This example extracts the unmanaged and managed versions of the AdventureWorks solution to a folder using the SolutionPackager tool. The managed version of solution must exist in the same folder as the unmanaged solution and end with the name _managed.zip (e.g. AdventureWorks_managed.zip).
#>
function Expand-CrmSolution {
    param (
        # The source solution zip file to extract. See the /zipfile parameter of the SolutionPackager tool.
        [Parameter(Mandatory, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ZipFile,

        # The path and name of an .xml file containing file mapping directives. See the /map parameter of the SolutionPackager tool.
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$MappingXmlFile,

        # The package type to process. See the /packagetype parameter of the SolutionPackager tool.
        [Parameter(Mandatory, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("Unmanaged","Managed","Both")]
        [string]$PackageType,

        # The folder path to store the extracted solution file. See the /folder parameter of the SolutionPackager tool.
        [Parameter(Mandatory, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Folder
    )
    process
    {
        # remove the existing extracted solution folder before creating it
        Remove-Item -Path $Folder -Force -Recurse -ErrorAction SilentlyContinue

        # sleep for 1 second to avoid the solution packager error "Access to the path '<path-to-folder>' is denied".
        Start-Sleep -Seconds 1

        $solutionPackagerArgs = "/nologo",
                                "/action:Extract",
                                "/zipfile:$ZipFile",
                                "/packagetype:$PackageType",
                                "/folder:$Folder"

        if($MappingXmlFile) {
            $solutionPackagerArgs += "/map:$MappingXmlFile"
        }

        # extract the solutions
        & "$(GetSolutionPackagerFolder)\SolutionPackager.exe" $solutionPackagerArgs
    }
}

<#
.Synopsis
   Packs and zips a folder of Configuration Migration tool generated files previously created from the Expand-CrmData cmdlet.
.DESCRIPTION
   This function packs and zips the folders and files created from Expand-CrmData processing of a Configuration Migration tool generated zip file.
.EXAMPLE
   Compress-CrmData -Folder 'C:\temp\data\AdventureWorks' -ZipFile 'C:\temp\packed\AdventureWorksData.zip'

   This example processes the contenets of the specified -Folder with an already exported data set from an AdventureWorks organization and saves the packed zip file to the specified -ZipFile.
#>
function Compress-CrmData {
    param (
        # The folder path of an unpacked Configuation Migration tool generated zip file.
        [Parameter(Mandatory, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Folder,

        # The zip file path to create after packing the configuration data files.
        [Parameter(Mandatory, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ZipFile
    )

    CrmConfigurationPackager -Pack -Path $Folder -DestinationPath $ZipFile
}

<#
.Synopsis
   Extracts and unpacks a Configuration Migration tool generated zip file to individual files.
.DESCRIPTION
   This function extracts a Configuration Migration tool generated zip file and unpacks the .xml files into separate files and folders, where each entity is stored in its own folder and each record is stored in its own .xml file inside the entity folder.
.EXAMPLE
   Expand-CrmData -ZipFile 'C:\temp\export\AdventureWorksData.zip' -Folder 'C:\temp\data\AdventureWorks'

   This example extracts the data zip file exported from the AdventureWorks organization and unpacks the contents to the specified -Folder.
#>
function Expand-CrmData {
    param (
        # The path and filename to the Configuration Migration tool generated zip file.
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        $ZipFile,

        # The folder path to store the unpacked records.
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        $Folder
    )
    process
    {
        CrmConfigurationPackager -Extract -Path $ZipFile -DestinationPath $Folder
    }
}

<#
.Synopsis
   Exports a list of solutions from a CRM organization.
.DESCRIPTION
   This function exports a list of solutions from a CRM organization.
.EXAMPLE
   >
   $CrmConnectionParameters = @{
       OrganizationName = 'contoso'
       ServerUrl = 'http://dyn365.contoso.com'
       Credential = [PSCredential]::new("contoso\administrator", ("pass@word1" | ConvertTo-SecureString -AsPlainText -Force))
   }

   $Solutions = @(
       [PSCustomObject]@{
           SolutionName = 'AdventureWorks'
           Managed = $false
           ZipFile = 'C:\temp\export\AdventureWorks.zip'
       },
       [PSCustomObject]@{
           SolutionName = 'AdventureWorks'
           Managed = $true
           ZipFile = 'C:\temp\export\AdventureWorks_managed.zip'
       }
   )

   Export-CrmSolutions -CrmConnectionParameters $CrmConnectionParameters -Solutions $Solutions

   This example prepares connection parameters for the -CrmConnectionParameters parameter, an array of PSCustomObject objects for defining the solutions to export, and then passing them to the Export-CrmSolutions function.
#>
function Export-CrmSolutions {
    param (
        # A [hashtable] of parameters to construct a [Microsoft.Xrm.Tooling.Connector.CrmServiceClient] object. See Get-CrmConnection for the available parameters.
        [Parameter(
            ValueFromPipelineByPropertyName=$true,
            Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [hashtable]
        $CrmConnectionParameters,

        # Publishes the customizations prior to exporting solutions when set to $true.
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$PublishCustomizations = $true,

        # An array of [PSCustomObject] objects describing the solutions to export. See the examples for the data structure to create for each [PSCustomObject].
        [ValidateNotNullOrEmpty()]
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [PSCustomObject[]]$Solutions
    )
    process
    {
        $CrmConnection = Get-CrmConnection @CrmConnectionParameters

        if($PublishCustomizations) {
            Write-Host 'Publishing all customizations'
            Publish-CrmAllCustomization -conn $CrmConnection
        }

        $Solutions | Invoke-ExportCrmSolution -CrmConnection $CrmConnection
    }
}

<#
.Synopsis
   Exports a solution from a CRM organization.
.DESCRIPTION
   This function exports an unmanaged solution from a CRM organization in a managed or unmanaged format and saves it to a zip file.
.EXAMPLE
   Invoke-ExportCrmSolution -CrmConnection (Get-CrmConnection -InteractiveMode) -SolutionName AdventureWorks -ZipFile 'C:\temp\export\AdventureWorks.zip'

   This example exports the AdventureWorks solution as unmanaged and saves it to a zip file.
.EXAMPLE
   Invoke-ExportCrmSolution -CrmConnection $crmConnection -SolutionName AdventureWorks -Managed -ZipFile 'C:\temp\export\AdventureWorks_managed.zip'

   This example exports the AdventureWorks solution as managed and saves it to a zip file.
.EXAMPLE
...Invoke-ExportCrmSolution -CrmConnection $crmConnection -SolutionName AdventureWorks -TargetVersion 8.0 -ZipFile 'C:\temp\export\AdventureWorks_managed.zip'

...This example exports the AdventureWorks solution as unmanaged, targets a specific version of CRM, and saves it to a zip file.

#>
function Invoke-ExportCrmSolution {
    param (
        # A CrmServiceClient object that is configured with a connection to a CRM organization. Use Get-CrmConnection to create one.
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [Microsoft.Xrm.Tooling.Connector.CrmServiceClient]$CrmConnection,

        # The unique solution name to export.
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]$SolutionName,

        # Exports the solution as managed when set to $true.
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$Managed,

        # The version number of CRM to target when exporting.
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]$TargetVersion,

        # The file path to save the exported solution zip file.
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]$ZipFile
    )
    process
    {
        $exportFolder = Split-Path -Path $ZipFile -Parent
        $exportFile = Split-Path -Path $ZipFile -Leaf
        New-Item -Path $exportFolder -ItemType Directory -Force | Out-Null

        Export-CrmSolution -conn $CrmConnection -SolutionName $SolutionName -Managed:$Managed -SolutionFilePath $exportFolder -TargetVersion $TargetVersion -SolutionZipFileName $exportFile
    }
}

function Format-Xml {
    [OutputType([string])]
    param (
        [Parameter(Mandatory=$true)]
        [xml]$Xml,

        [Parameter()]
        [int]$Indent=2
    )

    $StringWriter = New-Object System.IO.StringWriter
    $XmlWriter = New-Object System.Xml.XmlTextWriter $StringWriter
    $XmlWriter.Formatting = "indented"
    $XmlWriter.Indentation = $Indent
    $Xml.WriteContentTo($XmlWriter)
    $XmlWriter.Flush()
    $StringWriter.Flush()
    Write-Output $StringWriter.ToString()
}

function CreateRootSchema {
    param (
        [Parameter(Mandatory=$true)]
        [xml]$xml,

        [Parameter(Mandatory=$true)]
        [string]$DataPath

    )

    [xml]$rootSchema = $xml.CloneNode($true)

    foreach($entity in $rootSchema.entities.entity) {
        $entityFolder = Get-Item (Join-Path $DataPath $entity.name) -ErrorAction Ignore

        if($entityFolder) {

            # remove extraneous attributes that aren't helpful when viewing the file
            $removeAttributes = $entity.Attributes | Where-Object {$_.name -notin ('name','displayName')}
            foreach ($remove in $removeAttributes){
                $entity.RemoveAttribute($remove.name)
            }

            # remove child elements and make the entity element self-closing tag
            $entity.IsEmpty = $true

        } else {
            Write-Verbose "Removing $($entity.name) from root schema file due to no data for entity"
            $rootSchema.entities.RemoveChild($entity) | Out-Null
        }
    }

    return $rootSchema
}

function ExtractData {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Path,

        [Parameter(Mandatory=$true)]
        [string]$DestinationPath,

        [Parameter()]
        [switch]$ExcludeDefaultSubject
    )

    Write-Verbose "Extracting Data"

    [xml]$xml = Get-Content -Path $Path -Encoding UTF8

    foreach($entity in $xml.entities.entity) {
        $entityFolder = New-Item -ItemType Directory -Path (Join-Path -Path $DestinationPath -ChildPath $entity.name)
        $recordsFolder = New-Item -ItemType Directory -Path (Join-Path -Path $entityFolder -ChildPath 'records')

        foreach($record in $entity.records.record) {
            # unpack the documentbody field from annotations, by converting it from base 64 encoding and saving to the file system
            if($entity.name -eq 'annotation' -and ($record.field | Where-Object {$_.name -eq 'documentbody'})) {
                $documentbodyfield = $record.field | Where-Object {$_.name -eq 'documentbody'}
                $filenamefield = $record.field | Where-Object {$_.name -eq 'filename'}
                $documentbody = [Convert]::FromBase64String($documentbodyfield.value)
                $fileextension = [IO.Path]::GetExtension($filenamefield.value)
                $documentbodyfilename = "$($record.id)$fileextension"
                $documentbodyFolder = Join-Path -Path $recordsFolder -ChildPath 'documentbody'
                $documentbodyPath = Join-Path -Path $documentbodyFolder -ChildPath $documentbodyfilename
                New-Item -ItemType Directory -Path $documentbodyFolder -ErrorAction SilentlyContinue | Out-Null
                Write-Verbose "Writing file $documentbodyPath"
                [IO.File]::WriteAllBytes($documentbodyPath, $documentbody)

                # set the documentbody field value to the generated unpacked filename so the base 64 encoded text isn't written to disk and the file can be easily identified
                $documentbodyfield.value = [string](Join-Path -Path 'documentbody' -ChildPath $documentbodyfilename)
            }

            $recordPath = Join-Path -Path $recordsFolder -ChildPath "$($record.id).xml"

            Write-Verbose "Writing file $recordPath"
            Set-Content -Path $recordPath -Value (Format-Xml -xml $record.OuterXml) -Encoding UTF8
        }

        if($entity.m2mrelationships.GetType() -eq [System.Xml.XmlElement]) {
            $m2mPath = Join-Path -Path $entityFolder -ChildPath 'm2mrelationships.xml'
            Write-Verbose "Writing file $m2mPath"
            Set-Content -Path $m2mPath -Value (Format-Xml -xml $entity.m2mrelationships.OuterXml) -Encoding UTF8
        }
    }

    $rootData = CreateRootSchema -xml $xml -DataPath $DestinationPath

    # write back the condensed version of the data.xml file to the root of the folder
    Set-Content -Path (Join-Path -Path $DestinationPath -ChildPath 'data.xml') -Value (Format-Xml -xml $rootData.OuterXml) -Encoding UTF8
}

function PackData {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Path,

        [Parameter(Mandatory=$true)]
        [string]$DestinationPath,

        [Parameter()]
        [switch]$ExcludeDefaultSubject
    )

    $rootDataPath = Join-Path -Path $Path -ChildPath data.xml

    Write-Verbose "Loading file $rootDataPath"
    [xml]$xml = Get-Content -Path $rootDataPath -Encoding UTF8

    foreach($entity in $xml.entities.entity) {
        $entityFolder = Get-Item -Path (Join-Path -Path $Path -ChildPath $entity.name) -ErrorAction Ignore

        if($entityFolder -eq $null) {
            Write-Verbose "No data for entity $($entity.name), skipping data pack"
            $xml.entities.RemoveChild($entity) | Out-Null
            continue
        }

        $recordsFolder = Get-Item -Path (Join-Path -Path $entityFolder -ChildPath 'records')

        # load all the xml files that represent each CRM record
        $recordFiles = Get-ChildItem -Path $recordsFolder -Filter '*.xml'

        # create the stub records element where each CRM record will be stored
        $recordsNode = $xml.ImportNode(([xml]"<records />").DocumentElement, $true)

        $entity.AppendChild($recordsNode) | Out-Null

        # read the record xml for each CRM record from disk, and add it to the records element
        foreach($recordFile in $recordFiles) {
            Write-Verbose "Loading file $($recordFile.FullName)"
            $recordData = [xml](Get-Content -Path $recordFile.FullName -Encoding UTF8)

            # pack the documentbody field from annotations, by converting it from binary to base 64 encoding
            if($entity.name -eq 'annotation') {
                $documentbodyfield = $recordData.record.field | Where-Object {$_.name -eq 'documentbody'}

                if($documentbodyfield) {
                    $documentbodypath = Join-Path -Path $recordsFolder -ChildPath $documentbodyfield.value
                    Write-Verbose "Loading file $documentbodypath"
                    $documentbodyBytes = Get-Content -Path $documentbodypath -Encoding Byte -Raw
                    $documentbodybase64 = [Convert]::ToBase64String($documentbodyBytes)
                    $documentbodyfield.value = $documentbodybase64
                }
            }

            $recordDataNode = $xml.ImportNode($recordData.DocumentElement, $true)
            $recordsNode.AppendChild($recordDataNode) | Out-Null
        }

        # create the stub m2mrelationships element that will be replaced with the m2mrelationships.xml file
        $m2mStubNode = $xml.ImportNode(([xml]"<m2mrelationships />").DocumentElement, $true)
        $entity.AppendChild($m2mStubNode)| Out-Null

        # try load the m2mrelationships.xml file, if it exists, replace the m2mrelationships node
        $m2mPath = Join-Path -Path $entityFolder -ChildPath "m2mrelationships.xml"
        if(Test-Path -Path $m2mPath -PathType Leaf) {
            Write-Verbose "Loading file $m2mPath"
            $m2mData = [xml](Get-Content -Path $m2mPath -Encoding UTF8)
            $m2mNode = $xml.ImportNode($m2mData.DocumentElement, $true)
            $entity.ReplaceChild($m2mNode, $m2mStubNode) | Out-Null
        }
    }

    # write the packed version of the data.xml file to the root of the folder
    $dataOutPath = Join-Path -Path $DestinationPath -ChildPath 'data.xml'
    Write-Verbose "Writing file $dataOutPath"
    Set-Content -Path $dataOutPath -Value (Format-Xml -xml $xml.OuterXml) -Encoding UTF8
}

function ExtractSchema {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Path,

        [Parameter(Mandatory=$true)]
        [string]$DestinationPath
    )

    $xml = [xml](Get-Content -Path $Path -Encoding UTF8)

    foreach($entity in $xml.entities.entity) {
        $entityFolder = Get-Item -Path (Join-Path -Path $DestinationPath -ChildPath $entity.name) -ErrorAction Ignore
        if($entityFolder) {
            $schemaPath = Join-Path -Path $entityFolder -ChildPath 'data_schema.xml'
            Write-Verbose "Writing file $schemaPath"
            Set-Content -Path $schemaPath -Value (Format-Xml -xml $entity.OuterXml) -Encoding UTF8
        } else {
            Write-Verbose "No data for entity $($entity.name), skipping schema extract"
        }
    }

    $rootSchema = CreateRootSchema -xml $xml -DataPath $DestinationPath

    Set-Content -Path (Join-Path -Path $DestinationPath -ChildPath 'data_schema.xml') -Value (Format-Xml -xml $rootSchema.OuterXml) -Encoding UTF8
}

function PackSchema {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Path,

        [Parameter(Mandatory=$true)]
        [string]$DestinationPath
    )

    $rootSchemaPath = Join-Path -Path $Path -ChildPath data_schema.xml
    Write-Verbose "Loading file $rootSchemaPath"
    $xml = [xml](Get-Content -Path $rootSchemaPath -Encoding UTF8)

    foreach($entity in $xml.entities.entity) {
        $entityFolder = Get-Item -Path (Join-Path -Path $Path -ChildPath $entity.name) -ErrorAction Ignore
        if($entityFolder) {
            $schemaPath = Join-Path -Path $entityFolder -ChildPath 'data_schema.xml'
            Write-Verbose "Loading file $schemaPath"
            $entitySchema = [xml](Get-Content -Path $schemaPath -Encoding UTF8)
            $entitySchemaNode = $xml.ImportNode($entitySchema.DocumentElement, $true)
            $xml.entities.ReplaceChild($entitySchemaNode, $entity) | Out-Null
        } else {
            Write-Verbose "No data for entity $($entity.name), skipping schema pack"
            $xml.entities.RemoveChild($entity) | Out-Null
        }
    }

    if($SchemaOnly) {
        $outPath = $DestinationPath
    } else {
        # write the packed version of the data_schema.xml file to the root of the folder
        $outPath = Join-Path -Path $DestinationPath -ChildPath 'data_schema.xml'
    }

    Write-Verbose "Writing file $outPath"
    Set-Content -Path $outPath -Value (Format-Xml -xml $xml.OuterXml) -Encoding UTF8
}

function PackContentTypes {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Path,

        [Parameter(Mandatory=$true)]
        [string]$DestinationPath
    )

    $sourceContentTypesPath = Join-Path -Path $Path -ChildPath "[Content_Types].xml"
    $destinationContentTypesPath = Join-Path -Path $DestinationPath -ChildPath "[Content_Types].xml"
    Write-Verbose "Writing file $destinationContentTypesPath"
    Copy-Item -LiteralPath $sourceContentTypesPath -Destination $destinationContentTypesPath
}

function CrmConfigurationPackager {
    param (
        [Parameter(Mandatory=$true,ParameterSetName="Extract")]
        [Switch]$Extract,

        [Parameter(Mandatory=$true,ParameterSetName="Pack")]
        [Switch]$Pack,

        [Parameter(Mandatory=$true)]
        [string]$Path,

        [Parameter(Mandatory=$true)]
        [string]$DestinationPath,

        # remove the default subject when extracting the data
        [Parameter(ParameterSetName="Extract")]
        [switch]$ExcludeDefaultSubject = $true,

        # convert the packed version of the data to a zip file
        [Parameter(ParameterSetName="Pack")]
        [switch]$Compress = $true,

        # only pack the schema
        [Parameter(ParameterSetName="Pack")]
        [switch]$SchemaOnly
    )

    if($Extract) {

        if(Get-Item -Path $DestinationPath -OutVariable DestinationFullPath -ErrorAction Ignore) {
            Write-Verbose "Removing destination path before creating: $DestinationPath"

            Remove-Item -Path $DestinationFullPath -Recurse -Force
        }

        if([IO.Path]::GetExtension($Path) -eq '.zip') {
            Expand-Archive -Path $Path -DestinationPath $DestinationPath
        } else {
            Copy-Item -Path $Path -Destination $DestinationPath -Recurse
        }

        $dataPath = Join-Path -Path $DestinationPath -ChildPath data.xml
        $schemaPath = Join-Path -Path $DestinationPath -ChildPath data_schema.xml

        ExtractData -Path $dataPath -DestinationPath $DestinationPath -ExcludeDefaultSubject:$ExcludeDefaultSubject
        ExtractSchema -Path $schemaPath -DestinationPath $DestinationPath
    } elseif($Pack)  {

        # when target is a zip file, pack the contents to a temporary folder, then delete the temporary folder when done
        if([IO.Path]::GetExtension($DestinationPath) -eq '.zip') {
            $extractPath = Join-Path -Path ([IO.Path]::GetDirectoryName($DestinationPath)) -ChildPath (([IO.Path]::GetFileNameWithoutExtension(($DestinationPath)) + (Get-Date -Format '-yyyy-mm-dd-HHmmss')))
        } else {
            $extractPath = $DestinationPath
        }

        if(!$SchemaOnly -and !(Test-Path -Path $extractPath)) {
            Write-Verbose "Creating folder $extractPath"
            New-Item -Path $extractPath -ItemType Directory | Out-Null
        }

        PackSchema -Path $Path -DestinationPath $extractPath

        if(!$SchemaOnly) {
            PackData -Path $Path -DestinationPath $extractPath
            PackContentTypes -Path $Path -DestinationPath $extractPath

            # when target is a zip file, create the zip file, then delete the temporary folder
            if([IO.Path]::GetExtension($DestinationPath) -eq '.zip') {
                Write-Verbose "Writing file $DestinationPath"
                Compress-Archive -Path (Join-Path $extractPath '*') -DestinationPath $DestinationPath -Force
                Write-Verbose "Deleting folder $extractPath"
                Remove-Item -Path $extractPath -Recurse -Force
            }
        }
    }
}

<#
.Synopsis
   Creates a Package Deployer package for use with the Dynamics CRM Package Deployer.
.DESCRIPTION
   This function creates a package for use with the Dynamics CRM Package deployer included in the Dynamics 365 SDK. The Package Deployer documentation is located online at https://msdn.microsoft.com/en-us/library/dn688182.aspx. A package is prepared from a ConfigurationMigration tool data zip file and one or more solution zip files. The package is by default stored in a folder named Adoxio.Dynamics.ImportPackage within the PackageDeployer folder included in the Dynamics 365 SDK.
.EXAMPLE
   New-CrmPackage -DataZipFile 'C:\temp\packed\AdventureWorksData.zip' -SolutionZipFiles 'C:\temp\solutions\AdventureWorksEntities.zip','C:\temp\solutions\AdventureWorksProcesses.zip'

   This example creates a package from a data zip file and 2 solution files.
.EXAMPLE
   New-CrmPackage -SolutionZipFiles 'C:\temp\solutions\AdventureWorksEntities.zip','C:\temp\solutions\AdventureWorksProcesses.zip'

   This example creates a package from 2 solution files. No data will be imoprted.
.EXAMPLE
   New-CrmPackage -DataZipFile 'C:\temp\packed\AdventureWorksData.zip' -SolutionZipFiles 'C:\temp\solutions\AdventureWorksEntities.zip','C:\temp\solutions\AdventureWorksProcesses.zip' -ImportData:$false

   This example creates a package uses the -ImportData switch to disable the data import from being performed by Package Deployer.
.EXAMPLE
   New-CrmPackage -DataZipFile 'C:\temp\packed\AdventureWorksData.zip' -SolutionZipFiles 'C:\temp\solutions\AdventureWorksEntities.zip','C:\temp\solutions\AdventureWorksProcesses.zip' -PackageDllFile 'C:\temp\MyCrmPackage.dll' -PackageFolder 'C:\temp\PackageOutput'

   This example creates a package and supplies a path to -PackageDllFile to change which DLL assembly Package Deployer will use when performing an import, and it supplies a path to -PackageFolder to control the output location of the solution zip files, data zip file, and generated ImportConfig.xml file.
#>
function New-CrmPackage {
    param (
        # The path and filename to a Configuration Migration tool generated zip file.
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $DataZipFile,

        # A list file paths to solution zip files to be imported. The order is significant controls the order in which solutions will be imported into the CRM.
        [Parameter(Mandatory, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $SolutionZipFiles,

        # Whether the data import should be performed by Package Deployer. Default is $true.
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]
        $ImportData = $true,

        # The file path of the assembly (.dll) containing the package definition. Do not supply a value to use the default behavior of using Adoxio.Dynamics.ImportPackage.dll included in this module.
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $PackageDllFile,

        # The folder path to the package to import. Do not supply a value to use the default behavior of using the Adoxio.Dynamics.ImportPackage folder inside the CRM SDK's PackageDeployer folder.
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $PackageFolder = "$(GetPackageDeployerFolder)\Adoxio.Dynamics.ImportPackage"
    )
    process
    {
        if(-not $PackageDllFile) {
            # use Adoxio.Dynamics.ImportPackage.dll included in the module if one hasn't been supplied
            $PackageDllFile = Join-Path -Path $PSScriptRoot -ChildPath Adoxio.Dynamics.ImportPackage.dll
        }

        # create the package folder if it doesn't already exist
        New-Item -ItemType Directory -Path $PackageFolder -Force | Out-Null

        # remove any existing items already in the package folder to prevent potentially stale files from being deployed
        Remove-Item -Path (Join-Path -Path $PackageFolder -ChildPath *) -Recurse

        # copy the solutions and data to the package directory
        @($SolutionZipFiles,$DataZipFile) | Where-Object { $_ -ne "" } | Copy-Item -Destination $PackageFolder

        # generate the ImportConfig.xml file and copy it to the package directory
        NewCrmImportConfigXml -DataZipFile $DataZipFile -SolutionZipFiles $SolutionZipFiles -ImportData:$ImportData -PackageFolder $PackageFolder

        # copy the package dll to the package directory
        Copy-Item -Path $PackageDllFile -Destination (Split-Path $PackageFolder) -ErrorAction SilentlyContinue
    }
}

<#
.SYNOPSIS
    Imports a package to a Microsoft Dynamics CRM instance.
.DESCRIPTION
    The Invoke-ImportCrmPackage cmdlet imports a package to a CRM instance. Internally it registers the necessary Package Deployer
    cmdlets prior to invoking the Import-CrmPackage cmdlet. See help for Import-CrmPackage for additional information on importing packages.
.EXAMPLE
    $CrmConnectionParameters = @{
            OrganizationName = 'contoso'
            ServerUrl = 'http://dyn365.contoso.com'
            Credential = [PSCredential]::new("contoso\administrator", ("pass@word1" | ConvertTo-SecureString -AsPlainText -Force))
    }

    Invoke-ImportCrmPackage -CrmConnectionParameters $CrmConnectionParameters
.EXAMPLE
    $CrmConnectionParameters = @{
            OrganizationName = 'contoso'
            ServerUrl = 'http://dyn365.contoso.com'
            Credential = [PSCredential]::new("contoso\administrator", ("pass@word1" | ConvertTo-SecureString -AsPlainText -Force))
    }

    Invoke-ImportCrmPackage -PackageDeployerFolder C:\Dynamics365SDK\Tools\PackageDeployer -PackageFolder C:\Dynamics365SDK\Tools\PackageDeployer -PackageName Adoxio.Dynamics.ImportPackage.dll -CrmConnectionParameters $CrmConnectionParameters
#>
function Invoke-ImportCrmPackage {
    param(
        # Specifies the path to the Package Deployer folder.
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $PackageDeployerFolder = "$(GetPackageDeployerFolder)",

        # The folder path to the package to import.
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $PackageFolder = "$(GetPackageDeployerFolder)\Adoxio.Dynamics.ImportPackage",

        # The name of the assembly (.dll) containing the package definition.
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $PackageName = "Adoxio.Dynamics.ImportPackage.dll",

        # A [hashtable] of parameters to construct a [Microsoft.Xrm.Tooling.Connector.CrmServiceClient] object. See Get-CrmConnection for the available parameters.
        [Parameter(Mandatory, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [hashtable]
        $CrmConnectionParameters
    )
    process
    {
        # the current version of ssl/tls
        $securityProtocolVersion = [Net.ServicePointManager]::SecurityProtocol

        try {
            # register and run the Import-CrmPackage cmdlet in a job, to avoid file locking and other negative side effects to the current PowerShell session
            $job = Start-Job -ScriptBlock {

                # inherit the version of ssl/tls inside the job
                [Net.ServicePointManager]::SecurityProtocol = $using:securityProtocolVersion

                $crmConnectionParams = $using:CrmConnectionParameters
                
                Push-Location $using:PackageDeployerFolder

                if(Test-Path .\PowerShell) { # CRM 8.x SDK
                    cd .\PowerShell
                } elseif(Test-Path .\Microsoft.Xrm.Tooling.PackageDeployment.Powershell) { # CRM 9.x SDK
                    cd .\Microsoft.Xrm.Tooling.PackageDeployment.Powershell
                } else {
                    throw "Package Deployer PowerShell module not found, verify it is installed."
                }

                Import-Module .\Microsoft.Xrm.Tooling.CrmConnector.Powershell.dll
                Import-Module .\Microsoft.Xrm.Tooling.PackageDeployment.Powershell.dll
                # fully qualify the call to Get-CrmConnection to use the version from the package deployer to avoid a potential conflict with the version distributed with Microsoft.Xrm.Data.Powershell
                $crmConnection = Microsoft.Xrm.Tooling.CrmConnector.Powershell\Get-CrmConnection @crmConnectionParams

                Pop-Location

                Import-CrmPackage –CrmConnection $crmConnection –PackageDirectory (Split-Path $using:PackageFolder) –PackageName $using:PackageName -Verbose
            }

            # output results from the job until it completes
            while($job.HasMoreData) {
                $output = Receive-Job -Job $job
                if($output) { Write-Host $output }
                Start-Sleep -Milliseconds 200
            }
       }
       finally { # use finally to ensure these steps are taken even if the script execution is stopped
           # remove the background job
           Remove-Job -Job $job -Force
       }
    }
}

function NewCrmImportConfigXml {
    param (
        [string]$DataZipFile,
        [string[]]$SolutionZipFiles,
        [switch]$ImportData,
        [string]$PackageFolder
    )

    if($DataZipFile -and $ImportData) {
        $datazipfilename = Split-Path -Path $DataZipFile -Leaf
        $dataimportattribute = "crmmigdataimportfile=""$datazipfilename"""
    } else {
        $dataimportattribute = 'crmmigdataimportfile=""'
    }

    $solutionsXml = ""
    foreach($zipFile in $SolutionZipFiles) {
        $solutionzipfilename = Split-Path -Path $zipFile -Leaf
        $solutionsXml = $solutionsXml + "<configsolutionfile solutionpackagefilename=""$solutionzipfilename"" />`n"
    }

    $importConfig = @"
<?xml version="1.0" encoding="utf-16"?>
<configdatastorage xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                                                                         installsampledata="false"
                                                                         waitforsampledatatoinstall="false"
                                                                         agentdesktopzipfile=""
                                                                         agentdesktopexename=""
                                                                         $dataimportattribute>
  <solutions>
    $solutionsXml
  </solutions>
</configdatastorage>
"@

    Set-Content -Value (Format-Xml -xml $importConfig) -Path $PackageFolder\ImportConfig.xml -Encoding Unicode
}

<#
.Synopsis
   Creates a new CRM organization on a remote server by restoring from a backup.
.DESCRIPTION
   This function creates a new CRM organization on a remote server by restoring a backup of an existing CRM organization database.
.EXAMPLE
   Restore-CrmRemoteOrganization -ComputerName dyn365.contoso.com -Credential $credential -OrganizationName contoso -SqlBackupFile 'C:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\Backup\new_MSCRM.bak' -SqlDataFile 'C:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\DATA\contoso_MSCRM.mdf' -SqlLogFile 'C:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\DATA\contoso_MSCRM_log.ldf'

   This example connects to the server dyn365.contoso.com with the supplied credentials and creates a CRM organization named 'contoso' by restoring a database backup file 'new_MSCRM.bak'.
.EXAMPLE
   Restore-CrmRemoteOrganization -ComputerName dyn365.contoso.com -Credential $credential -OrganizationName contoso -SqlBackupFile 'C:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\Backup\new_MSCRM.bak' -SqlDataFile 'C:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\DATA\contoso_MSCRM.mdf' -SqlLogFile 'C:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\DATA\contoso_MSCRM_log.ldf' -Force

   This example replaces an existing CRM organization with the -Force parameter.
#>
function Restore-CrmRemoteOrganization {
    param (
        # The name of the CRM server
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        # The credentials for accessing the CRM server via PowerShell remoting
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]$Credential,

        # The name of the CRM organization to create
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$OrganizationName,

        # The file path to the SQL backup file of an organization to restore
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SqlBackupFile,

        # The file path to the new SQL database data file to create
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SqlDataFile,

        # The file path to the new SQL database log file to create
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SqlLogFile,

        # Overwrites an existing organization if one with the same name already exists
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$Force
    )

    try {
        # connect to the server
        $session = New-PSSession -ComputerName $ComputerName -Credential $Credential

        # import and execute the script to create a new CRM organization
        Invoke-Command -Session $session -ScriptBlock {
            # the use of -Force:(Write-Output $using:Force) is done to avoid the error 'A Using variable cannot be retrieved'.
            Restore-CrmOrganization -Name $using:OrganizationName -SqlServerName $using:ComputerName -SqlBackupFile $using:SqlBackupFile -SqlDataFile $using:SqlDataFile -SqlLogFile $using:SqlLogFile -Force:(Write-Output $using:Force)
        }
    }
    finally { # use finally to ensure the session is removed if the script execution is stopped
        if($session -eq $null) {
            Write-Error "Unable to establish a PowerShell remoting session to $ComputerName. Ensure the computer is turned on, PowerShell remoting is enabled, and remoting is verified to work using the Enter-PSSession command."
        } else {
            Remove-PSSession -Session $session
        }
    }
}

<#
.Synopsis
   Deletes an existing CRM organization from a local CRM server.
.DESCRIPTION
   This function deletes a CRM organization on a local CRM server by deleting the CRM organization and deleting the SQL database.
.EXAMPLE
  Remove-CrmOrganization -SqlServerName dyn365.contoso.com -OrganizationName Northwind

  This example shows how to delete an organization named Northwind on the SQL server named dyn365.contoso.com.
#>
function Remove-CrmOrganization
{
    param (
        # The name of the database and organization to delete
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        # The name of the SQL server to perform the database deletion operation on
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SqlServerName
    )

    # add the CRM cmdlets
    Add-PSSnapin Microsoft.Crm.PowerShell

    if(Test-CrmOrganization -UniqueName $Name) {
        # remove the CRM organization from deployment manager
        Write-Host "Removing organization: $Name"

        Disable-CrmOrganization -Name $Name
        Microsoft.Crm.PowerShell\Remove-CrmOrganization -Name $Name

        # load the SQL assembly
        [Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.Smo") | Out-Null

        # connect to the SQL Server
        $sqlServer = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Server($SqlServerName)

        # delete the database
        $dbName = "$($Name)_MSCRM"
        Write-Host "Removing database: $dbName"
        $sqlServer.KillAllProcesses($dbName)
        $sqlServer.KillDatabase($dbName)
    } else {
        Write-Host "Organization $Name does not exist, skipping deletion."
    }

}

<#
.Synopsis
   Deletes an existing CRM organization from a remote CRM server.
.DESCRIPTION
   This function deletes a CRM organization by using PowerShell remoting to connect to a remote CRM Server, removing the CRM organization and deleting the SQL database.
.EXAMPLE
  Remove-CrmRemoteOrganization -ComputerName dyn365.contoso.com -OrganizationName Northwind -Credential $Credential

  This example shows how to delete an organization named Northwind on the server named dyn365.contoso.com using the supplied credentials for PowerShellremoting.
#>
function Remove-CrmRemoteOrganization
{
    param (
        # The name of the CRM server to connect to and perform a CRM organization deletion
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$ComputerName,

        # The name of the database and organization to delete
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$OrganizationName,

        # The credentials for accessing the CRM server via PowerShell remoting
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [System.Management.Automation.PSCredential]$Credential
    )

    # connect to the server
    $session = New-PSSession -ComputerName $ComputerName -Credential $Credential

    # import and execute the script to create a new CRM organization
    Invoke-Command -Session $session -ScriptBlock {
        Remove-CrmOrganization -Name $using:OrganizationName -SqlServerName $using:ComputerName
    }

    # end the session
    Remove-PSSession -Session $session
}

<#
.Synopsis
   Creates a new CRM organzation on a local CRM server by restoring from a backup.
.DESCRIPTION
   This function creates a new CRM organization on a local CRM server by restoring a backup of an existing CRM organization database.
.EXAMPLE
   Restore-CrmOrganization -Name contoso -SqlServerName dyn365.contoso.com -SqlBackupFile 'C:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\Backup\new_MSCRM.bak' -SqlDataFile 'C:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\DATA\contoso_MSCRM.mdf' -SqlLogFile 'C:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\DATA\contoso_MSCRM_log.ldf'

   This example creates a CRM organization named 'contoso' by restoring a database backup file 'new_MSCRM.bak'.
.EXAMPLE
   Restore-CrmOrganization -Name contoso -SqlServerName dyn365.contoso.com -SqlBackupFile 'C:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\Backup\new_MSCRM.bak' -SqlDataFile 'C:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\DATA\contoso_MSCRM.mdf' -SqlLogFile 'C:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\DATA\contoso_MSCRM_log.ldf' -Force

   This example replaces an existing CRM organization with the -Force parameter.
#>
function Restore-CrmOrganization
{
    param(
        # The name of the database and organization to create
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        # The name of the SQL server to perform database restore operations on
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $SqlServerName,

        # The file path to the SQL backup file of an organization to restore
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SqlBackupFile,

        # The file path to the new SQL database data file to create
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SqlDataFile,

        # The file path to the new SQL database log file to create
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SqlLogFile,

        # Overwrites an existing database and organization if one with the same name already exists
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]$Force
    )
    process
    {
        # add the CRM cmdlets
        Add-PSSnapin Microsoft.Crm.PowerShell

        # only restore if an organization with the name isn't present
        if(Test-CrmOrganization -UniqueName $Name) {
            if($Force) {
                Remove-CrmOrganization -Name $Name -SqlServerName $SqlServerName
            }
            else {
                Write-Warning "CRM Organization '$Name' already exists, skipping restore"
                return
            }
        }

        [Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SmoExtended') | Out-Null
        $data = New-Object Microsoft.SqlServer.Management.Smo.RelocateFile("mscrm", $SqlDataFile)
        $log = New-Object Microsoft.SqlServer.Management.Smo.RelocateFile("mscrm_log", $SqlLogFile)

        Write-Host "Restoring database: $Name"
        Push-Location
        Restore-SqlDatabase -ServerInstance $SqlServerName -Database "$($Name)_MSCRM" -BackupFile $SqlBackupFile -RelocateFile $data,$log
        Pop-Location

        Write-Host "Importing organization: $Name"
        $importJobId = Import-CrmOrganization –DatabaseName "$($Name)_MSCRM" -DisplayName $Name -Name $Name –SqlServerName localhost –SrsUrl http://localhost/reportserver -UserMappingMethod ByAccount
        $importStatus = Get-CrmOperationStatus –OperationId $importJobId
        while($importStatus.State -ne 'Completed') {
            Write-Host $importStatus.State
            $importStatus = Get-CrmOperationStatus –OperationId $importJobId
            Start-Sleep -Seconds 5
        }
        Write-Host $importStatus.State
    }
}

function Edit-CrmDataFile {
    [CmdletBinding()]
    param (
        # The path to an existing Configuration Migration tool data.xml file.
        [Parameter(Mandatory, ValueFromPipelineByPropertyName=$true)]
        [string]$Path,

        # The path to store the modified Configuration Migration tool data.xml file.
        [Parameter(Mandatory, ValueFromPipelineByPropertyName=$true)]
        [string]$Destination,

        # A predicate for choosing whether an entity should be included. A comparison will be performed against every <entity> XmlNode, with a matching result causing the <entity> XmlNode to be retained, and non-matching items removed from the XML.
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [scriptblock]
        $EntityFilter,

        # Specifies the script block that is used to filter the fields that will be included from all entities during export. A matching result will cause the field to be retained, and non-matching items removed from the XML. This will primarily be used to exclude certain fields though negation comparision operators (e.g. -notin).
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [scriptblock]
        $FieldFilter,

        # Specifies the hashtable of entity names and scriptblocks that are used to filter the fields that will be included from specified entities. A matching result will cause the field to be included from the specified entity.
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({
            !($_.Keys.ForEach{$_ -is [string]} -contains $false -or
              $_.Values.ForEach{$_ -is [scriptblock]} -contains $false)
        })]
        [ValidateNotNullOrEmpty()]
        [hashtable]
        $EntityFieldFilters,

        [switch]
        $ReplaceRecordIds,

        [ValidateNotNullOrEmpty()]
        [scriptblock]
        $ReplaceRecordIdScriptBlock = {
            param (
                [Parameter(Mandatory)]
                [string]
                $Id
            )

            return ([System.Guid]::NewGuid()).Guid
        }
    )

    $xml = [xml](Get-Content -Path $Path -Encoding UTF8)

    if($EntityFilter) {
        $keepEntities = $xml.entities.entity | Where-Object -FilterScript $EntityFilter
        $removeEntities = $xml.entities.entity | Where-Object -FilterScript {$_ -notin $keepEntities}
        foreach ($entity in $removeEntities) {
            Write-Verbose "Removing entity from schema: $($entity.name)"
            $xml.entities.RemoveChild($entity) | Out-Null
        }
    }

    if($FieldFilter) {
        foreach($record in $xml.entities.entity.records.record) {
            $keepFields = $record.ChildNodes | Where-Object -FilterScript $FieldFilter
            $removeFields = $record.ChildNodes | Where-Object -FilterScript {$_ -notin $keepFields}
            foreach ($remove in $removeFields) {
                Write-Verbose "Removing field from record id $($record.id): $($remove.name)"
                $record.RemoveChild($remove) | Out-Null
            }
        }
    }

    if($EntityFieldFilters) {
        foreach($entity in $xml.entities.entity) {
            # if a fields filter has been specified for the current entity
            if($filter = $EntityFieldFilters[$entity.name]) {
                foreach($record in $entity.records.record) {
                    $keepFields = $record.ChildNodes | Where-Object -FilterScript $filter
                    $removeFields = $record.ChildNodes | Where-Object -FilterScript {$_ -notin $keepFields}
                    foreach ($remove in $removeFields) {
                        Write-Verbose "Removing field from entity $($entity.name): $($remove.name)"
                        $record.RemoveChild($remove) | Out-Null
                    }
                }
            }
        }
    }

    $formattedXml = Format-Xml -Xml $xml

    if($ReplaceRecordIds) {
        $formattedXml = [Text.StringBuilder]::new($formattedXml)

        $totalCount = $xml.entities.entity.records.record.id.Count
        $counter = 0
        foreach($id in $xml.entities.entity.records.record.id) {
            Write-Progress -Activity "Replace record IDs" -Status "Replacing record ID $id" -PercentComplete (($counter += 1) / $totalCount * 100)
            $newId = & $ReplaceRecordIdScriptBlock -Id $id
            $formattedXml.Replace($id, $newId) | Out-Null
        }

        Write-Progress -Activity "Replace record IDs" -Completed
    }

    Set-Content -Path $Destination -Value $formattedXml -Encoding UTF8
}

<#
.Synopsis
   Modifies a Configuration Migration tool schema file.
.DESCRIPTION
   This function takes a Configuration Migration tool schema file and modifies its contents to control the list of entities and fields that are included during an export, and the settings to use when importing the records uusing the Configuration Migration tool and Package Deployer.
.EXAMPLE
   Edit-CrmSchemaFile -Path C:\temp\schema-original.xml -Destination C:\temp\schema-modified.xml -EntityFilter {$_.name -in 'account,'contact'}

   This example modifies a schema file using the -EntityFilter parameter to specify only the account and contact entities should be included in the destination file. All other entities are removed from the schema file.
.EXAMPLE
   Edit-CrmSchemaFile -Path C:\temp\schema-original.xml -Destination C:\temp\schema-modified.xml -DisableAllEntityPlugins

   This example modifies a schema file using the -DisableAllEntityPlugins parameter to specify all entities should have plugins disabled on them during import.
.EXAMPLE
   Edit-CrmSchemaFile -Path C:\temp\schema-original.xml -Destination C:\temp\schema-modified.xml -DisableAllEntityPlugins

   This example modifies a schema file using the -DisableAllEntityPlugins parameter to specify all entities should have plugins disabled on them during import.
.EXAMPLE
   Edit-CrmSchemaFile -Path C:\temp\schema-original.xml -Destination C:\temp\schema-modified.xml -DisableEntityPluginsFilter {$_.name -in 'account','contact'}

   This example modifies a schema file using the -DisableEntityPluginsFilter parameter to specify only the account and contact entities should have plugins disabled on them during import.
.EXAMPLE
   Edit-CrmSchemaFile -Path C:\temp\schema-original.xml -Destination C:\temp\schema-modified.xml -UpdateComparePrimaryIdFilter {$_.name -notin 'account','contact'}

   This example modifies a schema file using the -UpdateComparePrimaryIdFilter parameter to specify all entities, except for account and contact, should match on their primaryid field during import.
.EXAMPLE
   Edit-CrmSchemaFile -Path C:\temp\schema-original.xml -Destination C:\temp\schema-modified.xml -UpdateComparePrimaryNameFilter {$_.name -in 'uom','uomschedule'}

   This example modifies a schema file using the -UpdateComparePrimaryNameFilter parameter to specify that the uom and uomschedule entities should match on their primaryname field during import. The Configuration Migration tool and Package Deployer match on primaryname by default, making this parameter unnecessary unless wanting to explicity define the entities that will be matched by their primaryname.
.EXAMPLE
   Edit-CrmSchemaFile -Path C:\temp\schema-original.xml -Destination C:\temp\schema-modified.xml -EntityUpdateCompareFields @{abs_autonumberedentity = 'abs_entitylogicalname'; incident = 'title','ticketnumber'}

   This example modifies a schema file using the -EntityUpdateCompareFields parameter to specify that the abs_autonumberedentity entity should match records using the abs_entitylogicalname field, and the incident entity should match records using both the title and ticketnumber fields.
.EXAMPLE
   Edit-CrmSchemaFile -Path C:\temp\schema-original.xml -Destination C:\temp\schema-modified.xml -FieldFilter {$_.name -notin 'createdby','createdon','createdonbehalfby','importsequencenumber','modifiedby','modifiedon','modifiedonbehalfby'}

   This example modifies a schema file using the -FieldFilter parameter to specify that all entities should include all their fields except for the ones listed in the array. This technique is useful for excluding fields where there are common fields across multipel entities where their data is unnecessary to store in a source control system because the values are system generated, not meaningful, or not desirable to ever be imported into a target system.
.EXAMPLE
   Edit-CrmSchemaFile -Path C:\temp\schema-original.xml -Destination C:\temp\schema-modified.xml -EntityFieldFilters @{contact = {$_.name -like 'abs_*' -or $_.name -in 'contactid','createdon'}; team = {$_ -notin 'businessunitid','teamid','name','isdefault'} }

   This example modifies a schema file using the -EntityFieldFilters parameter to specify that the contact and team entities should only include specific fields. The contact entity matches on a wildcard to include fields that start with abs_ or the fields named contactid and createdon. The team entity uses the -notin comparison to include all fields except for the ones listed in the array.
#>
function Edit-CrmSchemaFile {
    [CmdletBinding()]
    param (
        # The path to an existing Configuration Migration tool schema file.
        [Parameter(Mandatory, ValueFromPipelineByPropertyName=$true)]
        [string]$Path,

        # The path to store the modified Configuration Migration tool schema file.
        [Parameter(Mandatory, ValueFromPipelineByPropertyName=$true)]
        [string]$Destination,

        # A predicate for choosing whether an entity should be exported. A comparison will be performed against every <entity> XmlNode, with a result of $true causing the <entity> XmlNode to be retained and resulting in the entity being exported.
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [scriptblock]
        $EntityFilter,

        # Use to disable all plugins on all entities during import.
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]
        $DisableAllEntityPlugins,

        # A predicate for choosing whether an entity should have its plugins disabled during import. A filter result of $true will cause the entity's plugins to be disabled.
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [scriptblock]
        $DisableEntityPluginsFilter,

        # Specifies the script block that is used to filter the entities that will match on their primaryid field during import. A filter result of $true will cause the entity to be matched on its primaryid field.
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [scriptblock]
        $UpdateComparePrimaryIdFilter,

        # Specifies the script block that is used to filter the entities that will match on their primaryname field during import. A filter result of $true will cause the entity to be matched on its primaryname field.
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [scriptblock]
        $UpdateComparePrimaryNameFilter,

        # Specifies a hashtable of entity names and field names to indicate one or more fields each entity will be matched on during import.
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({
            !($_.Keys.ForEach{$_ -is [string]} -contains $false -or
              $_.Values.ForEach{$_ -is [string] -or $_ -is [object[]]} -contains $false)
        })]
        [ValidateNotNullOrEmpty()]
        [hashtable]
        $UpdateCompareEntityFields,

        # Specifies the script block that is used to filter the fields that will be included from all entities during export. A filter result of $true will cause the field to be included from all entities during export. This will primarily be used to exclude certain fields though negation comparision operators (e.g. -notin).
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [scriptblock]
        $FieldFilter,

        # Specifies the hashtable of entity names and scriptblocks that are used to filter the fields that will be included from specified entities during export. A filter result of $true will cause the field to be included from the specified entity during export.
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({
            !($_.Keys.ForEach{$_ -is [string]} -contains $false -or
              $_.Values.ForEach{$_ -is [scriptblock]} -contains $false)
        })]
        [ValidateNotNullOrEmpty()]
        [hashtable]
        $EntityFieldFilters
    )
    process
    {
        if($PSCmdlet.MyInvocation.InvocationName -eq 'Set-CrmSchemaFile') {
            Write-Warning "$($PSCmdlet.MyInvocation.InvocationName) is a deprecated name and will be removed in a future version, use $($PSCmdlet.CommandRuntime) instead"
        }

        $xml = [xml](Get-Content -Path $Path -Encoding UTF8)

        if($EntityFilter) {
            $keepEntities = $xml.entities.entity | Where-Object -FilterScript $EntityFilter
            $removeEntities = $xml.entities.entity | Where-Object -FilterScript {$_ -notin $keepEntities}
            foreach ($entity in $removeEntities) {
                Write-Verbose "Removing entity from schema: $($entity.name)"
                $xml.entities.RemoveChild($entity) | Out-Null
            }
        }

        if($DisableAllEntityPlugins) {
            foreach($entity in $xml.entities.entity) {
                # disable plugins on the entity
                Write-Verbose "Disabling plugins on entity: $($entity.name)"
                $entity.SetAttribute("disableplugins", "true")
            }
        }

        if($DisableEntityPluginsFilter) {
            $matchedEntities = $xml.entities.entity | Where-Object -FilterScript $DisableEntityPluginsFilter
            foreach ($entity in $matchedEntities) {
                Write-Verbose "Disabling plugins on entity: $($entity.name)"
                $entity.SetAttribute("disableplugins", "true")
            }
        }

        if($UpdateComparePrimaryIdFilter) {
            $matchedEntities = $xml.entities.entity | Where-Object -FilterScript $UpdateComparePrimaryIdFilter
            foreach ($entity in $matchedEntities) {
                Write-Verbose "Setting updateCompare to primaryidfield on entity: $($entity.name)"
                # remove the updateCompare attribute from any fields to ensure we don't end up with any unintended fields having the attribute at the end
                $entity.fields.ChildNodes | Where-Object {$_.Attributes['updateCompare'] -ne $null} | ForEach-Object {$_.RemoveAttribute('updateCompare')}
                # set updateCompare on the entity's primaryidfield
                $entity.fields.ChildNodes | Where-Object {$_.name -eq $entity.primaryidfield} | ForEach-Object {
                    $updateCompare = $xml.CreateAttribute("updateCompare")
                    $updateCompare.Value = "true"
                    $_.Attributes.InsertBefore($updateCompare, $_.Attributes[0]) | Out-Null
                }
            }
        }

        if($UpdateComparePrimaryNameFilter) {
            $matchedEntities = $xml.entities.entity | Where-Object -FilterScript $UpdateComparePrimaryNameFilter
            foreach ($entity in $matchedEntities) {
                Write-Verbose "Setting updateCompare to primarynamefield on entity: $($entity.name)"
                # remove the updateCompare attribute from any fields to ensure we don't end up with any unintended fields having the attribute at the end
                $entity.fields.ChildNodes | Where-Object {$_.Attributes['updateCompare'] -ne $null} | ForEach-Object {$_.RemoveAttribute('updateCompare')}
                # set updateCompare on the entity's primaryidfield
                $entity.fields.ChildNodes | Where-Object {$_.name -eq $entity.primarynamefield} | ForEach-Object {
                    $updateCompare = $xml.CreateAttribute("updateCompare")
                    $updateCompare.Value = "true"
                    $_.Attributes.InsertBefore($updateCompare, $_.Attributes[0]) | Out-Null
                }
            }
        }

        if($UpdateCompareEntityFields) {
            foreach($entity in $xml.entities.entity) {
                # if a fields list has been specified for the current entity
                if($fields = $UpdateCompareEntityFields[$entity.name]) {
                    Write-Verbose "Setting updateCompare to $($fields -join ',') on entity: $($entity.name)"
                    # remove the updateCompare attribute from any fields to ensure we don't end up with any unintended fields having the attribute at the end
                    $entity.fields.ChildNodes | Where-Object {$_.Attributes['updateCompare'] -ne $null} | ForEach-Object {$_.RemoveAttribute('updateCompare')}

                    $entity.fields.ChildNodes | Where-Object {$_.name -in $fields} | ForEach-Object {
                        $updateCompare = $xml.CreateAttribute("updateCompare")
                        $updateCompare.Value = "true"
                        $_.Attributes.InsertBefore($updateCompare, $_.Attributes[0]) | Out-Null
                    }
                }
            }
        }

        if($FieldFilter) {
            foreach($entity in $xml.entities.entity) {
                $keepFields = $entity.fields.ChildNodes | Where-Object -FilterScript $FieldFilter
                $removeFields = $entity.fields.ChildNodes | Where-Object -FilterScript {$_ -notin $keepFields}
                foreach ($remove in $removeFields) {
                    Write-Verbose "Removing field from entity $($entity.name): $($remove.name)"
                    $entity.fields.RemoveChild($remove) | Out-Null
                }
            }
        }

        if($EntityFieldFilters) {
            foreach($entity in $xml.entities.entity) {
                # if a fields filter has been specified for the current entity
                if($filter = $EntityFieldFilters[$entity.name]) {
                    $keepFields = $entity.fields.ChildNodes | Where-Object -FilterScript $filter
                    $removeFields = $entity.fields.ChildNodes | Where-Object -FilterScript {$_ -notin $keepFields}
                    foreach ($remove in $removeFields) {
                        Write-Verbose "Removing field from entity $($entity.name): $($remove.name)"
                        $entity.fields.RemoveChild($remove) | Out-Null
                    }
                }
            }
        }

        Set-Content -Path $Destination -Value (Format-Xml -xml $xml.OuterXml) -Encoding UTF8
    }
}

function Test-CrmOrganization {
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]
        $UniqueName
    )
    begin
    {
        Add-PSSnapin Microsoft.Crm.PowerShell
    }
    process
    {
        $organization = Get-CrmOrganization | Where-Object { $_.UniqueName -eq $UniqueName }
        Write-Output ($organization -ne $null)
    }
}

function Show-CrmDiagnostics {
    param (
        [Parameter(Mandatory=$true)]
        [string]$OrganizationUrl
    )

    Start-Process "$OrganizationUrl/tools/diagnostics/diag.aspx"
}