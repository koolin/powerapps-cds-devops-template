@{

# Script module or binary module file associated with this manifest.
RootModule = 'Adoxio.Dynamics.DevOps.psm1'

# Version number of this module.
ModuleVersion = '0.8.1'

# ID used to uniquely identify this module
GUID = '7481fd7b-2563-4e29-b9ee-14d53943ff8e'

# Author of this module
Author = 'Adoxio'

# Company or vendor of this module
CompanyName = 'Adoxio Business Solutions'

# Copyright statement for this module
Copyright = '(c) 2018 KPMG Adoxio Business Solutions Ltd. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Adoxio.Dynamics.DevOps provides functions for performing Microsoft Dynamics 365 development and deployment (DevOps) oriented tasks.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '5.0'

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
DotNetFrameworkVersion = '4.6.1'

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
CLRVersion = '4.0'

# Processor architecture (None, X86, Amd64) required by this module
ProcessorArchitecture = 'None'

# Modules that must be imported into the global environment prior to importing this module
RequiredModules = @(
    @{ModuleName='Microsoft.Xrm.Data.Powershell'; ModuleVersion='2.8.0'; Guid='7df9c140-65c3-4862-b3bc-73fad633aae4'}
)

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @("*-*")

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @('Dynamics365','CRM','DevOps','ALM','adoxio')

        # A URL to the license for this module.
        LicenseUri = 'https://github.com/Adoxio/Adoxio.Dynamics.DevOps/blob/master/LICENSE'

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/Adoxio/Adoxio.Dynamics.DevOps'

        # A URL to an icon representing this module.
        IconUri = 'https://www.adoxio.com/adoxio-icon.png'

        # Release notes of this module
        ReleaseNotes = 'Dynamics 365 v9 compatibility'

    } # End of PSData hashtable

} # End of PrivateData hashtable

}
