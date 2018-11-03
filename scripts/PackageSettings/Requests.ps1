# the file contains the settings for:
#   - packing individual data files into a Configuration Migration Tool data zip file
#   - packing individual solution files into a zip file using the CRM SDK's solution packager tool
#   - creating a package of a data zip file and solution zip files for import using the CRM SDK's package deployer tool
#   - provisioning an organization in a local development environment from a database backup
param (
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [hashtable]
    $CrmConnectionParameters,

    [ValidateSet("Managed","Unmanaged")]
    [string]
    $PackageType = "Unmanaged"
)

$scriptsRoot = Split-Path -Parent $PSScriptRoot
$projectRoot = Split-Path -Parent $scriptsRoot
$solutionExt = if($PackageType -eq "Managed") { "_managed" }

@{
    ExtractedData = [PSCustomObject]@{
        Folder = "$projectRoot\crm\data\ResourceRequests"
        ZipFile = "$projectRoot\temp\packed\ResourceRequestsData.zip"
    }
    ExtractedSolutions = @(
        [PSCustomObject]@{
            Folder = "$projectRoot\crm\solutions\ResourceSkills"
            MappingXmlFile = "$projectRoot\crm\solutions\ResourceSkills.mappings.xml"
            PackageType = "Managed"
            ZipFile = "$projectRoot\temp\packed\ResourceSkills_managed.zip"
        },
        [PSCustomObject]@{
            Folder = "$projectRoot\crm\solutions\ResourceRequests"
            MappingXmlFile = "$projectRoot\crm\solutions\ResourceRequests.mappings.xml"
            PackageType = $PackageType
            ZipFile = "$projectRoot\temp\packed\ResourceRequests$solutionExt.zip"
        }
    )
    CrmPackageDefinition = @(
        [PSCustomObject]@{
            DataZipFile = "$projectRoot\temp\packed\ResourceSkillsData.zip"
            SolutionZipFiles = @(
                "$projectRoot\temp\packed\ResourceSkills_managed.zip",
                "$projectRoot\temp\packed\ResourceRequests$solutionExt.zip"
            ),
			PackageFolder = "$projectRoot\src\Demo.ResourceManagementDeployment\bin\Debug\PkgFolder\"
			PackageDllFile = "$projectRoot\src\Demo.ResourceManagementDeployment\bin\Debug\Demo.ResourceManagementDeployment.dll"
        }
    )
    #CrmOrganizationProvisionDefinition = [PSCustomObject]@{
    #    ComputerName = 'dyn365.contoso.com'
    #    Credential = [PSCredential]::new('contoso\administrator', ('pass@word1' | ConvertTo-SecureString -AsPlainText -Force))
    #    OrganizationName = $CrmConnectionParameters.OrganizationName
    #    SqlBackupFile = 'C:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\Backup\new_MSCRM.bak'
    #    SqlDataFile = "C:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\DATA\$($CrmConnectionParameters.OrganizationName)_MSCRM.mdf"
    #    SqlLogFile = "C:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\DATA\$($CrmConnectionParameters.OrganizationName)_MSCRM_log.ldf"
    #}
    #CrmPackageDeploymentDefinition = [PSCustomObject]@{
    #    CrmConnectionParameters = $CrmConnectionParameters
    #}
}