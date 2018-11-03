param (

    # The settings for the actions performed during the import
    [Parameter(Mandatory)]
    [ValidateSet("Full","Skills","Requests")] # update this list based on files in the ImportSettings folder
    [string]
    $ImportSettings,

    [ValidateSet("Managed","Unmanaged")]
    [string]
    $PackageType = "Managed",

    # The available actions to perform during the import
    [ValidateSet("All","Compress-CrmData","Compress-CrmSolution","New-CrmPackage","Generate-Package")]
    [string[]]
    $Actions = "All"
)

$global:ErrorActionPreference = "Continue"

$settings = & "$PSScriptRoot\PackageSettings\$ImportSettings.ps1" -PackageType $PackageType

if($settings.ExtractedData -and ("All" -in $Actions -or 'Compress-CrmData' -in $Actions)) {
    $settings.ExtractedData | Compress-CrmData
}

if($settings.ExtractedSolutions -and ("All" -in $Actions -or 'Compress-CrmSolution' -in $Actions)) {
    $settings.ExtractedSolutions | Compress-CrmSolution
}

if($settings.CrmPackageDefinition -and ("All" -in $Actions -or 'New-CrmPackage' -in $Actions)) {
    $settings.CrmPackageDefinition | New-CrmPackage
}

if($settings.CrmPackageDefinition -and ("Generate-Package" -in $Actions)) {
    # remove any existing items already in the package folder to prevent potentially stale files from being deployed
    Remove-Item -Path (Join-Path -Path $settings.CrmPackageDefinition.PackageFolder -ChildPath *) -Recurse

    # copy the solutions and data to the package directory
    @($settings.CrmPackageDefinition.SolutionZipFiles,$settings.CrmPackageDefinition.DataZipFile) | Where-Object { $_ -ne "" } | Copy-Item -Destination $settings.CrmPackageDefinition.PackageFolder

    # generate the ImportConfig.xml file and copy it to the package directory
    NewCrmImportConfigXml -DataZipFile $settings.CrmPackageDefinition.DataZipFile -SolutionZipFiles $settings.CrmPackageDefinition.SolutionZipFiles -ImportData:$true -PackageFolder $settings.CrmPackageDefinition.PackageFolder
}