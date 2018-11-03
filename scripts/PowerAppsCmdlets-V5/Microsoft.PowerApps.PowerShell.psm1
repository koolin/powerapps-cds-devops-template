Import-Module (Join-Path (Split-Path $script:MyInvocation.MyCommand.Path) "PowerApps-RestClientModule.psm1") -Force
Import-Module (Join-Path (Split-Path $script:MyInvocation.MyCommand.Path) "PowerApps-AuthModule.psm1") -Force

function Get-PowerAppEnvironment
{
 <#
 .SYNOPSIS
 Returns information about one or more PowerApps environments that the user has access to.
 .DESCRIPTION
 The Get-PowerAppEnvironment cmdlet looks up information about =one or more environments depending on parameters. 
 Use Get-Help Get-PowerAppEnvironment -Examples for more detail.
 .PARAMETER Filter
 Finds environments matching the specified filter (wildcards supported).
 .PARAMETER EnvironmentName
 Finds a specific environment.
 .PARAMETER Default
 Finds the default environment.
 .PARAMETER CreatedByMe
 Finds environments created by the calling user
 .EXAMPLE
 Get-PowerAppEnvironment
 Finds all environments within the tenant.
 .EXAMPLE
 Get-PowerAppEnvironment -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 Finds environment 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 .EXAMPLE
 Get-PowerAppEnvironment *Test*
 Finds all environments that contain the string "Test" in their display name.
  .EXAMPLE
 Get-PowerAppEnvironment -CreatedByMe
 Finds all environments that were created by the calling user
 #>
    [CmdletBinding(DefaultParameterSetName="Filter")]
    param
    (
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "Filter")]
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "Owner")]
        [string[]]$Filter,

        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [string]$EnvironmentName,
        
        [Parameter(Mandatory = $false, ParameterSetName = "Default")]
        [Switch]$Default,

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Parameter(Mandatory = $false, ParameterSetName = "Owner")]
        [Switch]$CreatedByMe,

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [Parameter(Mandatory = $false, ParameterSetName = "Default")]
        [Parameter(Mandatory = $false, ParameterSetName = "Owner")]
        [string]$ApiVersion = "2016-11-01"
    )

    if ($Default)
    {
        $getEnvironmentUri = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/environments/~default?`$expand=permissions&api-version={apiVersion}"
    
        $environmentResult = InvokeApi -Method GET -Route $getEnvironmentUri -ApiVersion $ApiVersion
    
        CreateEnvironmentObject -EnvObject $environmentResult
    }
    else
    {
        $createdByUserId = ""

        If($CreatedByMe)
        {
            $createdByUserId = $Global:currentSession.userId
        }

        $filterString = $Filter

        if (-not [string]::IsNullOrWhiteSpace($EnvironmentName))
        {
            $filterString = $EnvironmentName
        }
        
        $getAllEnvironmentsUri = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/environments?`$expand=permissions&api-version={apiVersion}"
    
        $environmentsResult = InvokeApi -Method GET -Route $getAllEnvironmentsUri -ApiVersion $ApiVersion
        
        Get-FilteredEnvironments -Filter $filterString -CreatedBy $createdByUserId -EnvironmentResult $environmentsResult
    }
}


function Get-PowerAppConnection(
)
{
    <#
    .SYNOPSIS
    Returns connections for the calling user.
    .DESCRIPTION
    The Get-PowerAppConnection returns the connections for a calling user.  The connections can be filtered by a specified environment or api.
    Use Get-Help Get-PowerAppConnection -Examples for more detail.
    .PARAMETER ConnectorNameFilter
    Finds connections created against a specific connector (wildcards supported), for example *twitter* will returns connections for the twitter connector.
    .PARAMETER ReturnFlowConnections
    Every flow that is created also has an associated connection created with it.  Those connections will only be returned if this flag is specified.
    .PARAMETER EnvironmentName
    Limit connections returned to those in a specified environment.
    .EXAMPLE
    Get-PowerAppConnection
    Finds all connections for which the user has access.
    .EXAMPLE
    Get-PowerAppConnection -ReturnFlowConnections
    Finds all connections for which the user has access., including the connection created for each flow that the user has access to.
    .EXAMPLE
    Get-PowerAppConnection -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
    Finds connections within the 3c2f7648-ad60-4871-91cb-b77d7ef3c239 environment for this user.
    .EXAMPLE
    Get-PowerAppConnection -ConnectorNameFilter *twitter*
    Finds all connections for this user created against the Twitter connector.
    .EXAMPLE
    Get-PowerAppConnection -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
    Finds connectinos for the current user within the 3c2f7648-ad60-4871-91cb-b77d7ef3c239 environment.
    .EXAMPLE
    Get-PowerAppConnection -ConnectionName a2956cf95ba441119d16dc2ef0ca1ff9 -EnvironmentName 87d7e1a3-6104-4889-a225-54a681b5532b
    Returns the connection details for the connectino with name a2956cf95ba441119d16dc2ef0ca1ff9.
    #>
    [CmdletBinding(DefaultParameterSetName="Connection")]
    param
    (
        [Parameter(Mandatory = $false,  Position = 0, ParameterSetName = "Connection", ValueFromPipelineByPropertyName = $true)]
        [string]$ConnectionName,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false)]
        [string]$ConnectorNameFilter,

        [Parameter(Mandatory = $false)]
        [switch]$ReturnFlowConnections,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2016-11-01"
    )
    process
    {
        $environments = @();

        if (-not [string]::IsNullOrWhiteSpace($EnvironmentName))
        {
            $environments += @{
                EnvironmentName = $EnvironmentName
            }
        }
        else {
            $environments = Get-PowerAppEnvironment
        }

        $flowFilter = "/providers/Microsoft.PowerApps/apis/shared_logicflows"
        $patternFlow = BuildFilterPattern -Filter $flowFilter

        $patternApi = BuildFilterPattern -Filter $ConnectorNameFilter

        $patternConnection = BuildFilterPattern -Filter $ConnectionName

        foreach($environment in $environments)
        {                        
            $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/connections`?api-version={apiVersion}&`$filter=environment%20eq%20%27{environment}%27" `
            | ReplaceMacro -Macro "{environment}" -Value $environment.EnvironmentName;
    
            $getConnectionsResponse = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion
            
            foreach($connection in $getConnectionsResponse.value) 
            {
                if (-not [string]::IsNullOrWhiteSpace($ConnectionName))
                {
                    if ($patternConnection.IsMatch($connection.name))
                    {
                        CreateConnectionObject -ConnectionObj $connection
                    }
                }
                elseif($patternFlow.IsMatch($connection.properties.apiId))
                {
                    If($ReturnFlowConnections)
                    {
                        CreateConnectionObject -ConnectionObj $connection
                    }
                }
                elseif ($patternApi.IsMatch($connection.properties.apiId)) 
                {
                    CreateConnectionObject -ConnectionObj $connection
                }
            }
        }
    }
}

function Remove-PowerAppConnection
{
 <#
 .SYNOPSIS
 Deletes the connection.
 .DESCRIPTION
 The Remove-PowerAppConnection permanently deletes the connection. 
 Use Get-Help Remove-PowerAppConnection -Examples for more detail.
 .PARAMETER ConnectionName
 The connection identifier.
 .PARAMETER ConnectorName
 The connection's connector name.
 .PARAMETER EnvironmentName
 The connection's environment.
 .EXAMPLE
 Remove-PowerAppConnection -ConnectionName 3c2f7648-ad60-4871-91cb-b77d7ef3c239 -ConnectorName shared_twitter -EnvironmentName Default-efecdc9a-c859-42fd-b215-dc9c314594dd
 Deletes the connection with name 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 #>
    [CmdletBinding(DefaultParameterSetName="Name")]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Name")]
        [string]$ConnectionName,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Name")]
        [string]$ConnectorName,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Name")]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [string]$ApiVersion = "2017-06-01"
    )

    process 
    {
        $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/apis/{connector}/connections/{connection}`?api-version={apiVersion}&`$filter=environment%20eq%20%27{environment}%27" `
        | ReplaceMacro -Macro "{connector}" -Value $ConnectorName `
        | ReplaceMacro -Macro "{connection}" -Value $ConnectionName `
        | ReplaceMacro -Macro "{environment}" -Value $EnvironmentName;

        $removeResult = InvokeApi -Method DELETE -Route $route -ApiVersion $ApiVersion

        If($removeResult -eq $null)
        {
            return $null
        }
        
        CreateHttpResponse($removeResult)
    }
}

function Get-PowerAppConnectionRoleAssignment
{
 <#
 .SYNOPSIS
 Returns the connection role assignments for a user or a connection. Owner role assignments cannot be deleted without deleting the connection resource.
 .DESCRIPTION
 The Get-PowerAppConnectionRoleAssignment functions returns all roles assignments for an connection or all connection roles assignments for a user (across all of their connections).  A connection's role assignments determine which users have access to the connection for using or building apps and flows and with which permission level (CanUse, CanUseAndShare) . 
 Use Get-Help Get-PowerAppConnectionRoleAssignment -Examples for more detail.
 .PARAMETER ConnectionName
 The connection identifier.
 .PARAMETER EnvironmentName
 The connections's environment. 
 .PARAMETER ConnectorName
 The connection's connector identifier.
 .PARAMETER PrincipalObjectId
 The objectId of a user or group, if specified, this function will only return role assignments for that user or group.
 .EXAMPLE
 Get-PowerAppConnectionRoleAssignment
 Returns all connection role assignments for the calling user.
 .EXAMPLE
 Get-PowerAppConnectionRoleAssignment -ConnectionName 3b4b9592607147258a4f2fb33517e97a -ConnectorName shared_sharepointonline -EnvironmentName ee1eef10-ba55-440b-a009-ce379f86e20c
 Returns all role assignments for the connection with name 3b4b9592607147258a4f2fb33517e97ain environment with name ee1eef10-ba55-440b-a009-ce379f86e20c for the connector named shared_sharepointonline
 .EXAMPLE
 Get-PowerAppConnectionRoleAssignment -ConnectionName 3b4b9592607147258a4f2fb33517e97a -ConnectorName shared_sharepointonline -EnvironmentName ee1eef10-ba55-440b-a009-ce379f86e20c -PrincipalObjectId 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 Returns all role assignments for the user, or group with an object of 3c2f7648-ad60-4871-91cb-b77d7ef3c239 for the connection with name 3b4b9592607147258a4f2fb33517e97ain environment with name ee1eef10-ba55-440b-a009-ce379f86e20c for the connector named shared_sharepointonline
 #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [string]$ConnectionName,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$ConnectorName,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false)]
        [string]$PrincipalObjectId,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2017-06-01"
    )

    process 
    {
        $selectedObjectId = $global:currentSession.UserId 

        if (-not [string]::IsNullOrWhiteSpace($ConnectionName))
        {
            if (-not [string]::IsNullOrWhiteSpace($PrincipalObjectId))
            {
                $selectedObjectId = $PrincipalObjectId;
            }
            else 
            {
                $selectedObjectId = $null     
            }
        }

        $pattern = BuildFilterPattern -Filter $selectedObjectId

        if (-not [string]::IsNullOrWhiteSpace($ConnectionName))
        {

            $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/apis/{connector}/connections/{connection}/permissions?api-version={apiVersion}&`$filter=environment eq '{environment}'" `
            | ReplaceMacro -Macro "{connector}" -Value $ConnectorName `
            | ReplaceMacro -Macro "{connection}" -Value $ConnectionName `
            | ReplaceMacro -Macro "{environment}" -Value $EnvironmentName;

            $connectionRoleResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion

            foreach ($connectionRole in $connectionRoleResult.Value)
            {
                if (-not [string]::IsNullOrWhiteSpace($PrincipalObjectId))
                {
                    if ($pattern.IsMatch($connectionRole.properties.principal.id ) -or
                        $pattern.IsMatch($connectionRole.properties.principal.email) -or 
                        $pattern.IsMatch($connectionRole.properties.principal.tenantId))
                    {
                        CreateConnectionRoleAssignmentObject -ConnectionRoleAssignmentObj $connectionRole -EnvironmentName $EnvironmentName
                    }
                }
                else 
                {    
                    CreateConnectionRoleAssignmentObject -ConnectionRoleAssignmentObj $connectionRole -EnvironmentName $EnvironmentName
                }
            }
        }
        else 
        {
            $connections = Get-PowerAppConnection

            foreach($connection in $connections)
            {
                Get-PowerAppConnectionRoleAssignment `
                    -ConnectionName $connection.ConnectionName `
                    -ConnectorName $connection.ConnectorName `
                    -EnvironmentName $connection.EnvironmentName `
                    -PrincipalObjectId $selectedObjectId `
                    -ApiVersion $ApiVersion
            }
        }
    }
}

function Set-PowerAppConnectionRoleAssignment
{
    <#
    .SYNOPSIS
    Sets permissions to the connection.
    .DESCRIPTION
    The Set-PowerAppConnectionRoleAssignment set up permission to connection depending on parameters. 
    Use Get-Help Set-PowerAppConnectionRoleAssignment -Examples for more detail.
    .PARAMETER ConnectionName
    The connection identifier.
    .PARAMETER EnvironmentName
    The connections's environment. 
    .PARAMETER ConnectorName
    The connection's connector identifier.
    .PARAMETER RoleName
    Specifies the permission level given to the connection: CanView, CanViewWithShare, CanEdit. Sharing with the entire tenant is only supported for CanView.
    .PARAMETER PrincipalType
    Specifies the type of principal this connection is being shared with; a user, a security group, the entire tenant.
    .PARAMETER PrincipalObjectId
    If this connection is being shared with a user or security group principal, this field specified the ObjectId for that principal. You can use the Get-UsersOrGroupsFromGraph API to look-up the ObjectId for a user or group in Azure Active Directory.
    .EXAMPLE
    Set-PowerAppConnectionRoleAssignment -PrincipalType Group -PrincipalObjectId b049bf12-d56d-4b50-8176-c6560cbd35aa -RoleName CanEdit -ConnectionName 3b4b9592607147258a4f2fb33517e97a -ConnectorName shared_vsts -EnvironmentName Default-55abc7e5-2812-4d73-9d2f-8d9017f8c877
    Give the specified security group CanEdit permissions to the connection with name 3b4b9592607147258a4f2fb33517e97a
    #> 
    [CmdletBinding(DefaultParameterSetName="User")]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$ConnectionName,

        [Parameter(Mandatory = $true, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$ConnectorName,

        [Parameter(Mandatory = $true, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $true, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("CanView", "CanViewWithShare", "CanEdit")]
        [string]$RoleName,

        [Parameter(Mandatory = $true, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("User", "Group", "Tenant")]
        [string]$PrincipalType,

        [Parameter(Mandatory = $false, ParameterSetName = "Tenant")]
        [Parameter(Mandatory = $true, ParameterSetName = "User")]
        [string]$PrincipalObjectId = $null,

        [Parameter(Mandatory = $false, ParameterSetName = "User")]
        [Parameter(Mandatory = $false, ParameterSetName = "Tenant")]
        [string]$ApiVersion = "2017-06-01"
    )

    process 
    {
        $TenantId = $Global:currentSession.tenantId

        if($PrincipalType -ne "Tenant") 
        {
            $userOrGroup = Get-UsersOrGroupsFromGraph -ObjectId $PrincipalObjectId
            $PrincipalEmail = $userOrGroup.Mail
        }

        $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/apis/{connector}/connections/{connection}/modifyPermissions?api-version={apiVersion}&`$filter=environment eq '{environment}'" `
        | ReplaceMacro -Macro "{connector}" -Value $ConnectorName `
        | ReplaceMacro -Macro "{connection}" -Value $ConnectionName `
        | ReplaceMacro -Macro "{environment}" -Value $EnvironmentName;

        #Construct the body 
        $requestbody = $null

        If ($PrincipalType -eq "Tenant")
        {
            $requestbody = @{ 
                delete = @()
                put = @(
                    @{ 
                        properties = @{
                            roleName = $RoleName
                            capabilities = @()
                            NotifyShareTargetOption = "Notify"
                            principal = @{
                                email = ""
                                id = $TenantId
                                type = $PrincipalType
                                tenantId = $TenantId
                            }          
                        }
                    }
                )
            }
        }
        else
        {
            $requestbody = @{ 
                delete = @()
                put = @(
                    @{ 
                        properties = @{
                            roleName = $RoleName
                            capabilities = @()
                            NotifyShareTargetOption = "Notify"
                            principal = @{
                                email = $PrincipalEmail
                                id = $PrincipalObjectId
                                type = $PrincipalType
                                tenantId = $TenantId
                            }               
                        }
                    }
                )
            }
        }
        
        $setConnectionRoleResult = InvokeApi -Method POST -Body $requestbody -Route $route -ApiVersion $ApiVersion

        CreateHttpResponse($setConnectionRoleResult)
    }
}

function Remove-PowerAppConnectionRoleAssignment
{
 <#
 .SYNOPSIS
 Deletes a connection role assignment record.
 .DESCRIPTION
 The Remove-PowerAppConnectionRoleAssignment deletes the specific connection role assignment
 Use Get-Help Remove-PowerAppConnectionRoleAssignment -Examples for more detail.
 .PARAMETER RoleId
 The id of the role assignment to be deleted.
 .PARAMETER ConnectionName
 The app identifier.
 .PARAMETER ConnectorName
 The connection's associated connector name
 .PARAMETER EnvironmentName
 The connection's environment. 
 .EXAMPLE
 Remove-PowerAppConnectionRoleAssignment -ConnectionName a2956cf95ba441119d16dc2ef0ca1ff9 -EnvironmentName 08b4e32a-4e0d-4a69-97da-e1640f0eb7b9 -ConnectorName shared_twitter -RoleId /providers/Microsoft.PowerApps/apis/shared_twitter/connections/a2956cf95ba441119d16dc2ef0ca1ff9/permissions/7557f390-5f70-4c93-8bc4-8c2faabd2ca0
 Deletes the app role assignment with an id of /providers/Microsoft.PowerApps/apps/f8d7a19d-f8f9-4e10-8e62-eb8c518a2eb4/permissions/tenant-efecdc9a-c859-42fd-b215-dc9c314594dd
 #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [string]$ConnectionName,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$ConnectorName,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$RoleId,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2017-06-01"
    )

    process 
    {
        $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/apis/{connector}/connections/{connection}/modifyPermissions`?api-version={apiVersion}&`$filter=environment%20eq%20%27{environment}%27" `
        | ReplaceMacro -Macro "{connector}" -Value $ConnectorName `
        | ReplaceMacro -Macro "{connection}" -Value $ConnectionName `
        | ReplaceMacro -Macro "{environment}" -Value $EnvironmentName;

        #Construct the body 
        $requestbody = $null
        
        $requestbody = @{ 
            delete = @(
                @{ 
                    id = $RoleId
                }
            )
        }
    
        $removeResult = InvokeApi -Method POST -Body $requestbody -Route $route -ApiVersion $ApiVersion

        If($removeResult -eq $null)
        {
            return $null
        }
        
        CreateHttpResponse($removeResult)
    }
}

function Get-PowerAppConnector(
)
{
    <#
    .SYNOPSIS
    Returns connectors for the calling user.
    .DESCRIPTION
    The Get-PowerAppConnector returns the Connector for a calling user.  The Connector can be filtered by a specified environment or to only return custom connectors created by users.
    Use Get-Help Get-PowerAppConnector -Examples for more detail.
    .PARAMETER Filter
    Finds connectors matching the specified filter (wildcards supported), searches against the Connector's Name and DisplayName
    .PARAMETER FilterNonCustomConnectors
    Setting this flag will filter out all of the shared connectors built by microsfot such as Twitter, SharePoint, OneDrive, etc.
    .PARAMETER EnvironmentName
    Limit connectors returned to those in a specified environment.
    .PARAMETER ConnectorName
    Limits the details returned to only a certain specific connector
    .PARAMETER ReturnConnectorSwagger
    This parameter can only be set if the ConnectorName is populated, and, when set, will return additional metdata for the connector such as the Swagger and runtime Urls.
    .EXAMPLE
    Get-PowerAppConnector
    Finds all connectors that a user has access to across all environments (shared connectors will be duplicated in the response).
    .EXAMPLE
    Get-PowerAppConnector -FilterNonCustomConnectors
    Finds all custom connectors for which the user has access.
    .EXAMPLE
    Get-PowerAppConnector -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
    Finds connectors within the 3c2f7648-ad60-4871-91cb-b77d7ef3c239 environment for this user.
    .EXAMPLE
    Get-PowerAppConnector -Filter *twitter*
    Finds all connectors (both shared and custom) with the name Twitter.
    .EXAMPLE
    Get-PowerAppConnector -ConnectorName shared_sharepointonline -EnvironmentName 87d7e1a3-6104-4889-a225-54a681b5532b -ReturnConnectorSwagger
    Returns the connector details (including the swagger) for the connector named shared_sharepointonline in environment 87d7e1a3-6104-4889-a225-54a681b5532b
    #>
    [CmdletBinding(DefaultParameterSetName="Filter")]
    param
    (
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "Filter")]
        [string[]]$Filter,

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [switch]$FilterNonCustomConnectors,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Connector", ValueFromPipelineByPropertyName = $true)]
        [string]$ConnectorName,

        [Parameter(Mandatory = $true, ParameterSetName = "Connector", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, ParameterSetName = "Filter", ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false, ParameterSetName = "Connector")]
        [switch]$ReturnConnectorSwagger,

        [Parameter(Mandatory = $false, ParameterSetName = "Connector")]
        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [string]$ApiVersion = "2016-11-01"

    )
    process 
    {
        $environments = @();

        if (-not [string]::IsNullOrWhiteSpace($EnvironmentName))
        {
            $environments += @{
                EnvironmentName = $EnvironmentName
            }
        }
        else {
            $environments = Get-PowerAppEnvironment
        }

        $userId = $Global:currentSession.userId
        $expandPermissions = "permissions(`$filter=maxAssignedTo(`'$userId`'))"

        $patternConnector = BuildFilterPattern -Filter $ConnectorName
        $patternFilter = BuildFilterPattern -Filter $Filter
        $patternSharedConnector =  BuildFilterPattern -Filter "Microsoft"

        foreach($environment in $environments)
        {            
            if($ReturnConnectorSwagger)
            {
                $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/apis/{connector}?`$expand={expandPermissions}&`$filter=environment%20eq%20%27{environment}%27&api-version={apiVersion}" `
                | ReplaceMacro -Macro "{expandPermissions}" -Value $expandPermissions `
                | ReplaceMacro -Macro "{connector}" -Value $ConnectorName `
                | ReplaceMacro -Macro "{environment}" -Value $environment.EnvironmentName;

                $getConnectorsResponse = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion

                $connectors = $getConnectorsResponse
            }
            else 
            {
                $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/apis?showApisWithToS=true?&`$expand={expandPermissions}&`$filter=environment%20eq%20%27{environment}%27&api-version={apiVersion}" `
                | ReplaceMacro -Macro "{expandPermissions}" -Value $expandPermissions `
                | ReplaceMacro -Macro "{environment}" -Value $environment.EnvironmentName;
        
                $getConnectorsResponse = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion

                $connectors = $getConnectorsResponse.value
            }

            foreach($connector in $connectors) 
            {
                if (-not [string]::IsNullOrWhiteSpace($ConnectorName))
                {
                    if ($patternConnector.IsMatch($connector.name))
                    {
                        CreateConnectorObject -ConnectorObj $connector -EnvironmentName $environment.EnvironmentName
                    }
                }
                elseif($patternFilter.IsMatch($connector.name) -or 
                    $patternFilter.IsMatch($ConnectorObj.properties.displayName))
                {
                    #If(-not($FilterNonCustomConnectors -and $patternSharedConnector.IsMatch($connector.properties.metadata.source)))
                    If(-not($FilterNonCustomConnectors -and $patternSharedConnector.IsMatch($connector.properties.publisher)))
                    {
                        CreateConnectorObject -ConnectorObj $connector -EnvironmentName $environment.EnvironmentName
                    }
                }
            }
        }
    }
}

function Remove-PowerAppConnector
{
 <#
 .SYNOPSIS
 Deletes the custom connector.
 .DESCRIPTION
 The Remove-PowerAppConnector permanently deletes the custom connector. 
 Use Get-Help Remove-PowerAppConnector -Examples for more detail.
 .PARAMETER ConnectorName
 The custom connector name.
 .PARAMETER EnvironmentName
 The connector's environment.
 .EXAMPLE
 Remove-PowerAppConnector -ConnectorName shared_api.5fb47d90c037a0f41d.5fa9f4751f014dccc8 -EnvironmentName Default-efecdc9a-c859-42fd-b215-dc9c314594dd
 Deletes the connection with name shared_api.5fb47d90c037a0f41d.5fa9f4751f014dccc8
 #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$ConnectorName,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2017-06-01"
    )

    process 
    {
        $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/apis/{connector}`?api-version={apiVersion}&`$filter=environment%20eq%20%27{environment}%27" `
        | ReplaceMacro -Macro "{connector}" -Value $ConnectorName `
        | ReplaceMacro -Macro "{environment}" -Value $EnvironmentName;

        $removeResult = InvokeApi -Method DELETE -Route $route -ApiVersion $ApiVersion

        If($removeResult -eq $null)
        {
            return $null
        }
        
        CreateHttpResponse($removeResult)
    }
}

function Get-PowerAppConnectorRoleAssignment
{
 <#
 .SYNOPSIS
 Returns the connector role assignments for a user or a connector.
 .DESCRIPTION
 The Get-PowerAppConnectorRoleAssignment functions returns all roles assignments for an connector or all connector roles assignments for a user (across all of their connectors).  A connector's role assignments determine which users have access to the connector for using or building apps and flows and with which permission level (CanEdit, CanView) . 
 Use Get-Help Get-PowerAppConnectorRoleAssignment -Examples for more detail.
 .PARAMETER EnvironmentName
 The connections's environment. 
 .PARAMETER ConnectorName
 The connection's connector identifier.
 .PARAMETER PrincipalObjectId
 The objectId of a user or group, if specified, this function will only return role assignments for that user or group.
 .EXAMPLE
 Get-PowerAppConnectionRoleAssignment
 Returns all connection role assignments for the calling user.
 .EXAMPLE
 Get-PowerAppConnectionRoleAssignment  -ConnectorName shared_sharepointonline -EnvironmentName ee1eef10-ba55-440b-a009-ce379f86e20c
 Returns all role assignments for the connector named shared_sharepointonline in the environment with name ee1eef10-ba55-440b-a009-ce379f86e20c 
 .EXAMPLE
 Get-PowerAppConnectionRoleAssignment -ConnectorName shared_sharepointonline -EnvironmentName ee1eef10-ba55-440b-a009-ce379f86e20c -PrincipalObjectId 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 Returns all role assignments for the user, or group with an object of 3c2f7648-ad60-4871-91cb-b77d7ef3c239 for the connector named shared_sharepointonline in the environment with name ee1eef10-ba55-440b-a009-ce379f86e20c 
 #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$ConnectorName,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false)]
        [string]$PrincipalObjectId,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2017-06-01"
    )

    process 
    {
        $selectedObjectId = $global:currentSession.UserId 

        if (-not [string]::IsNullOrWhiteSpace($ConnectorName))
        {
            if (-not [string]::IsNullOrWhiteSpace($PrincipalObjectId))
            {
                $selectedObjectId = $PrincipalObjectId;
            }
            else 
            {
                $selectedObjectId = $null     
            }
        }

        $pattern = BuildFilterPattern -Filter $selectedObjectId

        if (-not [string]::IsNullOrWhiteSpace($ConnectorName))
        {

            $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/apis/{connector}/permissions?api-version={apiVersion}&`$filter=environment eq '{environment}'" `
            | ReplaceMacro -Macro "{connector}" -Value $ConnectorName `
            | ReplaceMacro -Macro "{environment}" -Value $EnvironmentName;

            $connectorRoleResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion

            foreach ($connectorRole in $connectorRoleResult.Value)
            {
                if (-not [string]::IsNullOrWhiteSpace($PrincipalObjectId))
                {
                    if ($pattern.IsMatch($connectorRole.properties.principal.id ) -or
                        $pattern.IsMatch($connectorRole.properties.principal.email) -or 
                        $pattern.IsMatch($connectorRole.properties.principal.tenantId))
                    {
                        CreateConnectorRoleAssignmentObject -ConnectorRoleAssignmentObj $connectorRole -EnvironmentName $EnvironmentName
                    }
                }
                else 
                {    
                    CreateConnectorRoleAssignmentObject -ConnectorRoleAssignmentObj $connectorRole -EnvironmentName $EnvironmentName
                }
            }
        }
        else 
        {
            $connectors = Get-PowerAppConnector -FilterNonCustomConnectors

            foreach($connector in $connectors)
            {
                Get-PowerAppConnectorRoleAssignment `
                    -ConnectorName $connector.ConnectorName `
                    -EnvironmentName $connector.EnvironmentName `
                    -PrincipalObjectId $selectedObjectId `
                    -ApiVersion $ApiVersion
            }
        }
    }
}

function Remove-PowerAppConnectorRoleAssignment
{
 <#
 .SYNOPSIS
 Deletes a connector role assignment record.
 .DESCRIPTION
 The Remove-PowerAppConnectorRoleAssignment deletes the specific connector role assignment
 Use Get-Help Remove-PowerAppConnectorRoleAssignment -Examples for more detail.
 .PARAMETER RoleId
 The id of the role assignment to be deleted.
 .PARAMETER ConnectorName
 The connector name
 .PARAMETER EnvironmentName
 The connector's environment. 
 .EXAMPLE
 Remove-PowerAppConnectorRoleAssignment -EnvironmentName 08b4e32a-4e0d-4a69-97da-e1640f0eb7b9 -ConnectorName shared_twitter -RoleId /providers/Microsoft.PowerApps/apis/shared_twitter/connections/a2956cf95ba441119d16dc2ef0ca1ff9/permissions/7557f390-5f70-4c93-8bc4-8c2faabd2ca0
 Deletes the app role assignment with an id of /providers/Microsoft.PowerApps/apps/f8d7a19d-f8f9-4e10-8e62-eb8c518a2eb4/permissions/tenant-efecdc9a-c859-42fd-b215-dc9c314594dd
 #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false,  Position = 0, ValueFromPipelineByPropertyName = $true)]
        [string]$ConnectorName,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$RoleId,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2017-06-01"
    )

    process 
    {
        $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/apis/{connector}/modifyPermissions`?api-version={apiVersion}&`$filter=environment%20eq%20%27{environment}%27" `
        | ReplaceMacro -Macro "{connector}" -Value $ConnectorName `
        | ReplaceMacro -Macro "{environment}" -Value $EnvironmentName;

        #Construct the body 
        $requestbody = $null
        
        $requestbody = @{ 
            delete = @(
                @{ 
                    id = $RoleId
                }
            )
        }
    
        $removeResult = InvokeApi -Method POST -Body $requestbody -Route $route -ApiVersion $ApiVersion

        If($removeResult -eq $null)
        {
            return $null
        }
        
        CreateHttpResponse($removeResult)
    }
}

function Set-PowerAppConnectorRoleAssignment
{
    <#
    .SYNOPSIS
    Sets permissions to the connector.
    .DESCRIPTION
    The Set-PowerAppConnectorRoleAssignment set up permission to connector depending on parameters. 
    Use Get-Help Set-PowerAppConnectorRoleAssignment -Examples for more detail.
    .PARAMETER ConnectorName
    The connector identifier.
    .PARAMETER EnvironmentName
    The connector's environment. 
    .PARAMETER RoleName
    Specifies the permission level given to the connector: CanView, CanViewWithShare, CanEdit. Sharing with the entire tenant is only supported for CanView.
    .PARAMETER PrincipalType
    Specifies the type of principal this connector is being shared with; a user, a security group, the entire tenant.
    .PARAMETER PrincipalObjectId
    If this connector is being shared with a user or security group principal, this field specified the ObjectId for that principal. You can use the Get-UsersOrGroupsFromGraph API to look-up the ObjectId for a user or group in Azure Active Directory.
    .EXAMPLE
    Set-PowerAppConnectorRoleAssignment -PrincipalType Group -PrincipalObjectId b049bf12-d56d-4b50-8176-c6560cbd35aa -RoleName CanEdit -ConnectorName shared_vsts -EnvironmentName Default-55abc7e5-2812-4d73-9d2f-8d9017f8c877
    Give the specified security group CanEdit permissions to the connector with name shared_vsts
    #> 
    [CmdletBinding(DefaultParameterSetName="User")]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$ConnectorName,

        [Parameter(Mandatory = $true, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $true, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("CanView", "CanViewWithShare", "CanEdit")]
        [string]$RoleName,

        [Parameter(Mandatory = $true, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("User", "Group", "Tenant")]
        [string]$PrincipalType,

        [Parameter(Mandatory = $false, ParameterSetName = "Tenant")]
        [Parameter(Mandatory = $true, ParameterSetName = "User")]
        [string]$PrincipalObjectId = $null,

        [Parameter(Mandatory = $false, ParameterSetName = "User")]
        [Parameter(Mandatory = $false, ParameterSetName = "Tenant")]
        [string]$ApiVersion = "2017-06-01"
    )

    process 
    {
        $TenantId = $Global:currentSession.tenantId

        if($PrincipalType -ne "Tenant") 
        {
            $userOrGroup = Get-UsersOrGroupsFromGraph -ObjectId $PrincipalObjectId
            $PrincipalEmail = $userOrGroup.Mail
        }

        $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/apis/{connector}/modifyPermissions?api-version={apiVersion}&`$filter=environment eq '{environment}'" `
        | ReplaceMacro -Macro "{connector}" -Value $ConnectorName `
        | ReplaceMacro -Macro "{connection}" -Value $ConnectionName `
        | ReplaceMacro -Macro "{environment}" -Value $EnvironmentName;

        #Construct the body 
        $requestbody = $null

        If ($PrincipalType -eq "Tenant")
        {
            $requestbody = @{
                put = @(
                    @{ 
                        properties = @{
                            roleName = $RoleName
                            principal = @{
                                email = " "
                                id = $TenantId
                                type = $PrincipalType
                                tenantId = $TenantId
                            }          
                        }
                    }
                )
            }
        }
        else
        {
            $requestbody = @{ 
                delete = @()
                put = @(
                    @{ 
                        properties = @{
                            roleName = $RoleName
                            capabilities = @()
                            NotifyShareTargetOption = "Notify"
                            principal = @{
                                email = $PrincipalEmail
                                id = $PrincipalObjectId
                                type = $PrincipalType
                                tenantId = $TenantId
                            }               
                        }
                    }
                )
            }
        }
        
        $setConnectorRoleResult = InvokeApi -Method POST -Body $requestbody -Route $route -ApiVersion $ApiVersion

        CreateHttpResponse($setConnectorRoleResult)
    }
}

function Get-PowerApp
{
 <#
 .SYNOPSIS
 Returns information about one or more apps.
 .DESCRIPTION
 The Get-PowerApp looks up information about one or more apps depending on parameters. 
 Use Get-Help Get-PowerApp -Examples for more detail.
 .PARAMETER Filter
 Finds apps matching the specified filter (wildcards supported).
 .PARAMETER AppName
 Finds a specific id.
 .PARAMETER MyEditable
 Limits the query to only apps that are owned or where the user has CanEdit access, this filter is applicable only if the EnvironmentName parameter is populated.
 .PARAMETER EnvironmentName
 Limit apps returned to those in a specified environment.
 .EXAMPLE
 Get-PowerApp
 Finds all apps for which the user has access.
 .EXAMPLE
 Get-PowerApp -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 Finds apps within the 3c2f7648-ad60-4871-91cb-b77d7ef3c239 environment
 .EXAMPLE
 Get-PowerApp *PowerApps*
 Finds all app in the current environment that contain the string "PowerApps" in their display name.
 .EXAMPLE
 Get-PowerApp -AppName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 Returns the details for the app named 3c2f7648-ad60-4871-91cb-b77d7ef3c239.
 .EXAMPLE
 Get-PowerApp -MyEditable -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 Shows apps owned or editable by the current user within the 3c2f7648-ad60-4871-91cb-b77d7ef3c239 environment.
 #>
    [CmdletBinding(DefaultParameterSetName="Filter")]
    param
    (
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "Filter")]
        [string[]]$Filter,

        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "Name", ValueFromPipelineByPropertyName = $true)]
        [string]$AppName,

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Switch]$MyEditable,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [string]$ApiVersion = "2016-11-01"
    )

    process 
    {
        if (-not [string]::IsNullOrWhiteSpace($AppName))
        {
            $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/apps/{appName}?api-version={apiVersion}&`$expand=unpublishedAppDefinition" `
            | ReplaceMacro -Macro "{appName}" -Value $AppName;

            $appResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion

            CreateAppObject -AppObj $appResult;
        }
        else
        {
            $userId = $Global:currentSession.userId
            $expandPermissions = "permissions(`$filter=maxAssignedTo(`'$userId`'))"

            if(-not [string]::IsNullOrWhiteSpace($EnvironmentName))
            {
                If($MyEditable)
                {
                    $queryFilter = "environment eq '{environment}'"
                }
                else
                {
                    $queryFilter = "classification eq 'EditableApps' and environment eq '{environment}'"    
                }

                $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/apps?api-version={apiVersion}&`$expand={expandPermissions}&`$filter={queryFilter}&`$top=250" `
                | ReplaceMacro -Macro "{expandPermissions}" -Value $expandPermissions `
                | ReplaceMacro -Macro "{queryFilter}" -Value $queryFilter `
                | ReplaceMacro -Macro "{environment}" -Value (ResolveEnvironment -OverrideId $EnvironmentName);
            }
            else
            {
                $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/apps?api-version={apiVersion}&`$expand={expandPermissions}&`$top=250" `
                    | ReplaceMacro -Macro "{expandPermissions}" -Value $expandPermissions;
            }
            $appResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion

            $pattern = BuildFilterPattern -Filter $Filter

            foreach ($app in $appResult.Value)
            {
                if ($pattern.IsMatch($app.name) -or
                    $pattern.IsMatch($app.properties.displayName))
                {
                    CreateAppObject -AppObj $app
                }
            }
        }
    }
}

function Remove-PowerApp
{
 <#
 .SYNOPSIS
 Deletes the app.
 .DESCRIPTION
 The Remove-PowerApp permanently deletes the app. 
 Use Get-Help Remove-PowerApp -Examples for more detail.
 .PARAMETER AppName
 The app identifier.
 .EXAMPLE
 Remove-PowerApp -AppName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 Deletes the app with name 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 #>
    [CmdletBinding(DefaultParameterSetName="Name")]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Name", ValueFromPipelineByPropertyName = $true)]
        [string]$AppName,

        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [string]$ApiVersion = "2017-06-01"
    )

    process 
    {
        $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/apps/{appName}?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{appName}" -Value $AppName;

        $removeResult = InvokeApi -Method DELETE -Route $route -ApiVersion $ApiVersion

        CreateHttpResponse -ResponseObject $removeResult
    }
}

function Publish-PowerApp
{
 <#
 .SYNOPSIS
 Publishes the current 'draft' version of the app to be the 'live' version of the app.  All users of the app will be able to see the new version post-publishing.
 .DESCRIPTION
 The Publish-PowerApp publishes the draft version of the specified app to all users. 
 Use Get-Help Publish-PowerApp -Examples for more detail.
 .PARAMETER AppName
 The app identifier.
 .EXAMPLE
 Publish-PowerApp -AppName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 Publishes the draft vesrion of the app with name 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 #>
    [CmdletBinding(DefaultParameterSetName="Name")]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Name", ValueFromPipelineByPropertyName = $true)]
        [string]$AppName,

        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [string]$ApiVersion = "2017-06-01"
    )

    process 
    {
        $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/apps/{appName}/publish?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{appName}" -Value $AppName;

        $publishResult = InvokeApi -Method POST -Body @{} -Route $route -ApiVersion $ApiVersion

        CreateHttpResponse -ResponseObject $publishResult
    }
}

function Set-PowerAppDisplayName
{
 <#
 .SYNOPSIS
 Sets the app display name.
 .DESCRIPTION
 The Set-PowerAppDisplayName changes the display name of the app to the specified string.
 Use Get-Help Set-PowerAppDisplayName -Examples for more detail.
 .PARAMETER AppName
 The app identifier.
 .PARAMETER AppDisplayName
 The new display name fo the app.
 .EXAMPLE
 Set-PowerAppDisplayName -AppName 3c2f7648-ad60-4871-91cb-b77d7ef3c239 -AppDisplayName "New App Display Name"
 Set the display name of the app with id 3c2f7648-ad60-4871-91cb-b77d7ef3c239 to "New App Display Name"
 #>
    [CmdletBinding(DefaultParameterSetName="Name")]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Name", ValueFromPipelineByPropertyName = $true)]
        [string]$AppName,

        [Parameter(Mandatory = $true, ParameterSetName = "Name")]
        [string]$AppDisplayName,

        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [string]$ApiVersion = "2017-06-01"
    )

    process 
    {
        $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/apps/{appName}/displayName?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{appName}" -Value $AppName;

        $body = @{
            displayName = $AppDisplayName
        }

        $publishResult = InvokeApi -Method PUT -Body $body -Route $route -ApiVersion $ApiVersion
    }
}

function Get-PowerAppVersion
{
 <#
 .SYNOPSIS
 Returns all of versions of an app.  Whenever an PowerApps Studio ends, the changes made during the session are saved to the app's single draft version (i.e. the version with lifeCycleId=Draft). The most recent version with a lifeCycleId=Published is the version that is live to all users of the app.
 .DESCRIPTION
 The Get-PowerAppVersion returns all previous published versions of an app and the draft version if it exists. 
 Use Get-Help Get-PowerAppVersion -Examples for more detail.
 .PARAMETER AppName
 The app identifier.
 .PARAMETER LatestDraft
 Limits the query to only return the latest draft version of the app, if it exists.
 .PARAMETER LatestPublished
 Limits the query to only return the latest published version of the app.
 .EXAMPLE
 Get-PowerAppVersion -AppName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 Returns all versions of the app with name 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 .EXAMPLE
 Get-PowerAppVersion -AppName 3c2f7648-ad60-4871-91cb-b77d7ef3c239 -LatestDraft 
 Returns the draft version (if exists) of the app  with name 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 .EXAMPLE
 Get-PowerAppVersion -AppName 3c2f7648-ad60-4871-91cb-b77d7ef3c239 -LatestPublished
 Returns the latest published version of the app with name 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 #>
    [CmdletBinding(DefaultParameterSetName="Name")]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Name", ValueFromPipelineByPropertyName = $true)]
        [string]$AppName,

        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [Switch]$LatestDraft,

        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [Switch]$LatestPublished,

        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [string]$ApiVersion = "2017-06-01"
    )

    process 
    {
        $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/apps/{appName}/versions?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{appName}" -Value $AppName;

        $versionsResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion

        $latestPublishedDate = $null
        $latestPublishedAppVersion = $null     
        
        $publishedFound = $false
        $draftFound = $false

        foreach ($appVersion in $versionsResult.Value)
        {
            if ($LatestDraft)
            {
                if ($appVersion.properties.lifeCycleId -eq "Draft")
                {
                    $draftFound = $true
                    CreateAppVersionObject -AppVersionObj $appVersion  
                    break
                }
            }
            elseif ($LatestPublished)
            {
                if ($appVersion.properties.lifeCycleId -eq "Published")
                {
                    #if first time through seed the latest version
                    if ($publishedFound)
                    {
                        $publishedFound = $true
                        $latestPublishedDate = [DateTime] $appVersion.properties.AppVersion
                        $latestPublishedAppVersion = $appVersion                    
                    }
                    else 
                    {
                        $nextPublishedDate = [DateTime] $appVersion.properties.AppVersion  

                        #if there is a more recent published version replace it
                        if ($nextPublishedDate -gt $latestPublishedDate)
                        {
                            $latestPublishedDate = $nextPublishedDate
                            $latestPublishedAppVersion = $appVersion
                        }
                    }
                }
            }
            #if the caller just wants all versions return them
            else
            {
                CreateAppVersionObject -AppVersionObj $appVersion  
            }
        }

        #if the caller was asking for the latest published version, return it
        if($latestPublishedAppVersion)
        {
            CreateAppVersionObject -AppVersionObj $latestPublishedAppVersion  
        }

        #if the caller was asking for a draft and there was none, return null
        if ($LatestDraft -and (-not $draftFound))
        {
            return $null
        }
    }
}

function Restore-PowerAppVersion
{
 <#
 .SYNOPSIS
 Restores the current 'draft' version of the app to be the specified App Version. 
 .DESCRIPTION
 The Restore-PowerAppVersion publishes the draft version of the specified app to all users. 
 Use Get-Help Restore-PowerAppVersion -Examples for more detail.
 .PARAMETER AppName
 The app identifier.
 .PARAMETER AppVersionName
 The app version identifier (retrieved by calling Get-PowerAppVersion). 
 .PARAMETER ImmediatelyPublish
 If this parameter is specified, the specific App Version will immediately be published to be the 'live' version of the app available to all users.
 .EXAMPLE
 Restore -AppVersion -AppName 08b4e32a-4e0d-4a69-97da-e1640f0eb7b9 -AppVersionName 20180220T065310Z
 Restores the draft version of the app with name 08b4e32a-4e0d-4a69-97da-e1640f0eb7b9 to the state that was previously stored as app version 20180220T065310Z
 .EXAMPLE
 Restore -AppVersion -AppName 08b4e32a-4e0d-4a69-97da-e1640f0eb7b9 -AppVersionName 20180220T065310Z -ImmediatelyPublish
 Restores the 'live' version of the app with name 08b4e32a-4e0d-4a69-97da-e1640f0eb7b9 to the state that was previously stored as app version 20180220T065310Z
 #>
    [CmdletBinding(DefaultParameterSetName="Name")]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Name", ValueFromPipelineByPropertyName = $true)]
        [string]$AppName,

        [Parameter(Mandatory = $true, ParameterSetName = "Name", ValueFromPipelineByPropertyName = $true)]
        [string]$AppVersionName,

        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [Switch]$ImmediatelyPublish,

        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [string]$ApiVersion = "2017-06-01"
    )

    process 
    {
        $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/apps/{appName}/versions/{appVersionName}/promote?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{appName}" -Value $AppName `
        | ReplaceMacro -Macro "{appVersionName}" -Value $AppVersionName;

        $restoreResult = InvokeApi -Method POST -Body @{} -Route $route -ApiVersion $ApiVersion

        If($ImmediatelyPublish)
        {
            $pulishResult = Publish-PowerApp -AppName $AppName -ApiVersion $ApiVersion
        }
    }
}

function Get-PowerAppRoleAssignment
{
 <#
 .SYNOPSIS
 Returns the app roles assignments for a user or an app.
 .DESCRIPTION
 The Get-PowerAppRolesAssignment functions returns all roles assignments for an app or all roles assignments for a user (across all of their apps).  An app's role assignemnts  determine which users have access to an app and with which permission level (Owner, CanEdit, CanView) . 
 Use Get-Help Get-PowerAppRolesAssignment -Examples for more detail.
 .PARAMETER AppName
 The app identifier.
 .PARAMETER EnvironmentName
 The app's environment. 
 .PARAMETER PrincipalObjectId
 The objectId of a user or group, if specified, this function will only return role assignments for that user or group.
 .EXAMPLE
 Get-PowerAppRolesAssignment
 Returns all app role assignments for the calling user.
 .EXAMPLE
 Get-PowerAppRoleAssignment -AppName 3c2f7648-ad60-4871-91cb-b77d7ef3c239 -EnvironmentName 08b4e32a-4e0d-4a69-97da-e1640f0eb7b9
 Returns all role assignments for the app with name 3c2f7648-ad60-4871-91cb-b77d7ef3c239 in environment with name 08b4e32a-4e0d-4a69-97da-e1640f0eb7b9 
 .EXAMPLE
 Get-PowerAppRoleAssignment -AppName 3c2f7648-ad60-4871-91cb-b77d7ef3c239 -EnvironmentName 08b4e32a-4e0d-4a69-97da-e1640f0eb7b9 -PrincipalObjectId 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 Returns all role assignments for the user or group with an object of 3c2f7648-ad60-4871-91cb-b77d7ef3c239 for the app with name 3c2f7648-ad60-4871-91cb-b77d7ef3c239 in environment with name 08b4e32a-4e0d-4a69-97da-e1640f0eb7b9 
 #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [string]$AppName,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false)]
        [string]$PrincipalObjectId,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2017-06-01"
    )

    process 
    {
        $selectedObjectId = $global:currentSession.UserId 

        if (-not [string]::IsNullOrWhiteSpace($AppName))
        {
            if (-not [string]::IsNullOrWhiteSpace($PrincipalObjectId))
            {
                $selectedObjectId = $PrincipalObjectId;
            }
            else 
            {
                $selectedObjectId = $null     
            }
        }

        $pattern = BuildFilterPattern -Filter $selectedObjectId

        if (-not [string]::IsNullOrWhiteSpace($AppName))
        {
            $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/apps/{appName}/permissions?api-version={apiVersion}&`$filter=environment eq '{environment}'" `
            | ReplaceMacro -Macro "{appName}" -Value $AppName `
            | ReplaceMacro -Macro "{environment}" -Value $EnvironmentName;

            $appRoleResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion

            foreach ($appRole in $appRoleResult.Value)
            {
                if (-not [string]::IsNullOrWhiteSpace($PrincipalObjectId))
                {
                    if ($pattern.IsMatch($appRole.properties.principal.id ) -or
                        $pattern.IsMatch($appRole.properties.principal.email) -or 
                        $pattern.IsMatch($appRole.properties.principal.tenantId))
                    {
                        CreateAppRoleAssignmentObject -AppRoleAssignmentObj $appRole    
                    }
                }
                else 
                {    
                    CreateAppRoleAssignmentObject -AppRoleAssignmentObj $appRole
                }
            }
        }
        else 
        {
            $apps = Get-PowerApp

            foreach($app in $apps)
            {
                Get-PowerAppRoleAssignment `
                    -AppName $app.AppName `
                    -EnvironmentName $app.EnvironmentName `
                    -PrincipalObjectId $selectedObjectId `
                    -ApiVersion $ApiVersion
            }
        }
    }
}

function Remove-PowerAppRoleAssignment
{
 <#
 .SYNOPSIS
 Deletes an app roles assignment.
 .DESCRIPTION
 The Remove-PowerAppRoleAssignment deletes the specific app role assignment
 Use Get-Help Remove-PowerAppRolesAssignment -Examples for more detail.
 .PARAMETER RoleId
 The id of the role assignment to be deleted.
 .PARAMETER AppName
 The app identifier.
 .PARAMETER EnvironmentName
 The app's environment. 
 .EXAMPLE
 Remove-PowerAppRoleAssignment -AppName 3c2f7648-ad60-4871-91cb-b77d7ef3c239 -EnvironmentName 08b4e32a-4e0d-4a69-97da-e1640f0eb7b9 -RoleId /providers/Microsoft.PowerApps/apps/f8d7a19d-f8f9-4e10-8e62-eb8c518a2eb4/permissions/tenant-efecdc9a-c859-42fd-b215-dc9c314594dd
 Deletes the app role assignment with an id of /providers/Microsoft.PowerApps/apps/f8d7a19d-f8f9-4e10-8e62-eb8c518a2eb4/permissions/tenant-efecdc9a-c859-42fd-b215-dc9c314594dd
 #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [string]$AppName,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$RoleId,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2017-06-01"
    )

    process 
    {
        $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/apps/{appName}/modifyPermissions`?api-version={apiVersion}&`$filter=environment%20eq%20%27{environment}%27" `
        | ReplaceMacro -Macro "{appName}" -Value $AppName `
        | ReplaceMacro -Macro "{environment}" -Value $EnvironmentName;

        #Construct the body 
        $requestbody = $null
        
        $requestbody = @{ 
            delete = @(
                @{ 
                    id = $RoleId
                }
            )
        }
    

        $removeResult = InvokeApi -Method POST -Body $requestbody -Route $route -ApiVersion $ApiVersion

        If($removeResult -eq $null)
        {
            return $null
        }
        
        CreateHttpResponse($removeResult)
    }
}

function Set-PowerAppRoleAssignment
{
    <#
    .SYNOPSIS
    sets permissions to the app.
    .DESCRIPTION
    The Set-PowerAppRoleAssignments set up permission to app depending on parameters. 
    Use Get-Help Set-PowerAppRoleAssignment -Examples for more detail.
    .PARAMETER AppName
    App name for the one which you want to set permission.
    .PARAMETER EnvironmentName
    Limit app returned to those in a specified environment.
    .PARAMETER RoleName
    Specifies the permission level given to the app: CanView, CanViewWithShare, CanEdit. Sharing with the entire tenant is only supported for CanView.
    .PARAMETER PrincipalType
    Specifies the type of principal this app is being shared with; a user, a security group, the entire tenant.
    .PARAMETER PrincipalObjectId
    If this app is being shared with a user or security group principal, this field specified the ObjectId for that principal. You can use the Get-UsersOrGroupsFromGraph API to look-up the ObjectId for a user or group in Azure Active Directory.
    .EXAMPLE
    Set-PowerAppRoleAssignment -PrincipalType Group -PrincipalObjectId b049bf12-d56d-4b50-8176-c6560cbd35aa -RoleName CanEdit -AppName 1ec3c80c-c2c0-4ea6-97a8-31d8c8c3d488 -EnvironmentName Default-55abc7e5-2812-4d73-9d2f-8d9017f8c877
    Give the specified security group CanEdit permissions to the app with name 1ec3c80c-c2c0-4ea6-97a8-31d8c8c3d488 
    #> 
    [CmdletBinding(DefaultParameterSetName="User")]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$AppName,

        [Parameter(Mandatory = $true, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $true, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("CanView", "CanViewWithShare", "CanEdit")]
        [string]$RoleName,

        [Parameter(Mandatory = $true, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("User", "Group", "Tenant")]
        [string]$PrincipalType,

        [Parameter(Mandatory = $false, ParameterSetName = "Tenant")]
        [Parameter(Mandatory = $true, ParameterSetName = "User")]
        [string]$PrincipalObjectId = $null,

        [Parameter(Mandatory = $false, ParameterSetName = "User")]
        [Parameter(Mandatory = $false, ParameterSetName = "Tenant")]
        [string]$ApiVersion = "2016-11-01"
    )

    process 
    {
        $TenantId = $Global:currentSession.tenantId

        if($PrincipalType -ne "Tenant") 
        {
            $userOrGroup = Get-UsersOrGroupsFromGraph -ObjectId $PrincipalObjectId
            $PrincipalEmail = $userOrGroup.Mail
        }

        $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/apps/{appName}/modifyPermissions`?api-version={apiVersion}&`$filter=environment eq '{environment}'" `
        | ReplaceMacro -Macro "{appName}" -Value $AppName `
        | ReplaceMacro -Macro "{environment}" -Value (ResolveEnvironment -OverrideId $EnvironmentName);
    
        #Construct the body 
        $requestbody = $null

        If ($PrincipalType -eq "Tenant")
        {
            $requestbody = @{ 
                delete = @()
                put = @(
                    @{ 
                        properties = @{
                            roleName = $RoleName
                            capabilities = @()
                            NotifyShareTargetOption = "Notify"
                            principal = @{
                                email = ""
                                id = "null"
                                type = $PrincipalType
                                tenantId = $TenantId
                            }          
                        }
                    }
                )
            }
        }
        else
        {
            $requestbody = @{ 
                delete = @()
                put = @(
                    @{ 
                        properties = @{
                            roleName = $RoleName
                            capabilities = @()
                            NotifyShareTargetOption = "Notify"
                            principal = @{
                                email = $PrincipalEmail
                                id = $PrincipalObjectId
                                type = $PrincipalType
                                tenantId = "null"
                            }               
                        }
                    }
                )
            }
        }
        
        $setAppRoleResult = InvokeApi -Method POST -Body $requestbody -Route $route -ApiVersion $ApiVersion

        CreateHttpResponse($setAppRoleResult)
    }
}

function Get-PowerAppsNotification
{
 <#
 .SYNOPSIS
 Returns the PowerApps notifications for the calling users.
 .DESCRIPTION
 The Get-PowerAppsNotification functions returns all PowerApps notifications for t calling user, which inclues all records of cds data files they have exported and apps that have beens shared with them . 
 Use Get-Help Get-PowerAppsNotification -Examples for more detail.
 .EXAMPLE
 Get-PowerAppsNotification
 Returns all the PowerApps notifications for the calling user.
 #>
    [CmdletBinding(DefaultParameterSetName="User")]
    param
    (
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$UserId,

        [Parameter(Mandatory = $false, ParameterSetName = "User")]
        [string]$ApiVersion = "2017-06-01"
    )

    process 
    {
        $selectedUserId = $global:currentSession.UserId

        $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/objectIds/{objectId}/notifications?api-version={apiVersion}"`
            | ReplaceMacro -Macro "{objectId}" -Value $selectedUserId;

        $notificationResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion

        foreach ($notification in $notificationResult.Value)
        {
            CreatePowerAppsNotificationObject -PowerAppsNotificationObj $notification
        }
    }
}

function Get-FlowEnvironment
{
 <#
 .SYNOPSIS
 Returns information about one or more Flow environments that the user has access to.
 .DESCRIPTION
 The Get-FlowEnvironment cmdlet looks up information about one or more environments depending on parameters. 
 Use Get-Help Get-FlowEnvironment -Examples for more detail.
 .PARAMETER Filter
 Finds environments matching the specified filter (wildcards supported).
 .PARAMETER EnvironmentName
 Finds a specific environment.
 .PARAMETER Default
 Finds the default environment.
 .EXAMPLE
 Get-FlowEnvironment
 Finds all environments within the tenant.
 .EXAMPLE
 Get-FlowEnvironment -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 Finds environment 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 .EXAMPLE
 Get-FlowEnvironment *Test*
 Finds all environments that contain the string "Test" in their display name.
 #>
    [CmdletBinding(DefaultParameterSetName="Filter")]
    param
    (
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "Filter")]
        [string[]]$Filter,

        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "Name")]
        [string]$EnvironmentName,
        
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "Default")]
        [Switch]$Default,

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [string]$ApiVersion = "2016-11-01"
    )
    
    if ($Default)
    {
        $getEnvironmentUri = "https://{flowEndpoint}/providers/Microsoft.ProcessSimple/environments/~default?`$expand=permissions&api-version={apiVersion}"
    
        $environmentResult = InvokeApi -Method GET -Route $getEnvironmentUri -ApiVersion $ApiVersion
    
        CreateEnvironmentObject -EnvObject $environmentResult
    }
    elseif (-not [string]::IsNullOrWhiteSpace($EnvironmentName))
    {
        $getEnvironmentUri = "https://{flowEndpoint}/providers/Microsoft.ProcessSimple/environments/{environmentName}?`$expand=permissions&api-version={apiVersion}" `
            | ReplaceMacro -Macro "{environmentName}" -Value $EnvironmentName;
    
        $environmentResult = InvokeApi -Method GET -Route $getEnvironmentUri -ApiVersion $ApiVersion
    
        CreateEnvironmentObject -EnvObject $environmentResult
    }
    else
    {
        $getAllEnvironmentsUri = "https://{flowEndpoint}/providers/Microsoft.ProcessSimple/environments?`$expand=permissions&api-version={apiVersion}"
    
        $environmentsResult = InvokeApi -Method GET -Route $getAllEnvironmentsUri -ApiVersion $ApiVersion
        
        $pattern = BuildFilterPattern -Filter $Filter;

        foreach ($environment in $environmentsResult.Value)
        {
            if ($pattern.IsMatch($environment.name) -or
                $pattern.IsMatch($environment.properties.displayName))
            {
                CreateEnvironmentObject -EnvObject $environment;
            }
        }
    }
}

function Get-Flow
{
 <#
 .SYNOPSIS
 Returns information about one or more flows.
 .DESCRIPTION
 The Get-Flow looks up information about one or more flows depending on parameters. 
 Use Get-Help Get-Flow -Examples for more detail.
 .PARAMETER Filter
 Finds flows matching the specified filter (wildcards supported).
 .PARAMETER Flow
 Finds a specific id.
 .PARAMETER My
 Limits the query to only flows owned ONLY by the currently authenticated user.
 .PARAMETER Team
 Limits the query to flows owned by the currently authenticated user but shared with other users.
 .PARAMETER EnvironmentName
 Limit flows returned to those in a specified environment.
 .PARAMETER Top
 Limits the result size of the query. Defaults to 50.
 .EXAMPLE
 Get-Flow
 Finds all flows for which the user has access.
 .EXAMPLE
 Get-Flow -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 Finds flows within the 3c2f7648-ad60-4871-91cb-b77d7ef3c239 environment
 .EXAMPLE
 Get-Flow *PowerApps*
 Finds all flows in the current environment that contain the string "PowerApps" in their display name.
 .EXAMPLE
 Get-Flow -My
 Shows flows owned only by the current user.
 #>
    [CmdletBinding(DefaultParameterSetName="Filter")]
    param
    (
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "Filter")]
        [string[]]$Filter,

        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "Name")]
        [string]$FlowName,

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Switch]$My,

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Switch]$Team,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [int]$Top = 50,

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [string]$ApiVersion = "2016-11-01"
    )

    process 
    {
        if (-not [string]::IsNullOrWhiteSpace($FlowName))
        {
            $route = "https://{flowEndpoint}/providers/Microsoft.ProcessSimple/environments/{environment}/flows/{flowName}?api-version={apiVersion}" `
                | ReplaceMacro -Macro "{flowName}" -Value $FlowName `
                | ReplaceMacro -Macro "{environment}" -Value (ResolveEnvironment -OverrideId $EnvironmentName);

            $flowResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion

            CreateFlowObject -FlowObj $flowResult;
        }
        else
        {
            $flowFilter = "`$filter=all&";

            if ($My)
            {
                $flowFilter = "`$filter=search('personal')&";
            }
            elseif ($Team)
            {
                $flowFilter = "`$filter=search('team')&";
            }

            $route = "https://{flowEndpoint}/providers/Microsoft.ProcessSimple/environments/{environment}/flows?api-version={apiVersion}" `
                | ReplaceMacro -Macro "{flowFilter}" -Value $flowFilter `
                | ReplaceMacro -Macro "{environment}" -Value (ResolveEnvironment -OverrideId $EnvironmentName) `
                | ReplaceMacro -Macro "{topValue}" -Value $Top.ToString();

            $flowResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion

            $pattern = BuildFilterPattern -Filter $Filter;

            foreach ($flow in $flowResult.Value)
            {
                if ($pattern.IsMatch($flow.name) -or
                    $pattern.IsMatch($flow.properties.displayName))
                {
                    CreateFlowObject -FlowObj $flow
                }
            }
        }
    }
}


function Get-FlowOwnerRole
{
 <#
    .SYNOPSIS
    Gets owner permissions to the flow.
    .DESCRIPTION
    The Get-FlowOwnerRole 
    Use Get-Help Get-FlowOwnerRole -Examples for more detail.
    .PARAMETER EnvironmentName
    The environment of the flow.
    .PARAMETER FlowName
    Specifies the flow id.
    .PARAMETER Owner
    A objectId of the user you want to filter by.
    .EXAMPLE
    Get-FlowOwnerRole -Owner 53c0a918-ce7c-401e-98f9-1c60b3a723b3
    Returns all flow permissions across all environments for the user with an object id of 53c0a918-ce7c-401e-98f9-1c60b3a723b3
    .EXAMPLE
    Get-FlowOwnerRole -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239 -Owner 53c0a918-ce7c-401e-98f9-1c60b3a723b3
    Returns all flow permissions within environment with id 3c2f7648-ad60-4871-91cb-b77d7ef3c239 for the user with an object id of 53c0a918-ce7c-401e-98f9-1c60b3a723b3
    .EXAMPLE
    Get-FlowOwnerRole -FlowName 4d1f7648-ad60-4871-91cb-b77d7ef3c239 -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239 -Owner 53c0a918-ce7c-401e-98f9-1c60b3a723b3
    Returns all flow permissions for the flow with id 4d1f7648-ad60-4871-91cb-b77d7ef3c239 in environment 3c2f7648-ad60-4871-91cb-b77d7ef3c239 for the user with an object id of 53c0a918-ce7c-401e-98f9-1c60b3a723b3
    .EXAMPLE
    Get-FlowOwnerRole -FlowName 4d1f7648-ad60-4871-91cb-b77d7ef3c239 -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
    Returns all permissions for the flow with id 4d1f7648-ad60-4871-91cb-b77d7ef3c239 in environment 3c2f7648-ad60-4871-91cb-b77d7ef3c239
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [string]$FlowName,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false)]
        [string]$PrincipalObjectId,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2017-06-01"
    )

    process 
    {
        $selectedObjectId = $global:currentSession.UserId 

        if (-not [string]::IsNullOrWhiteSpace($FlowName))
        {
            if (-not [string]::IsNullOrWhiteSpace($PrincipalObjectId))
            {
                $selectedObjectId = $PrincipalObjectId;
            }
            else 
            {
                $selectedObjectId = $null     
            }
        }

        $pattern = BuildFilterPattern -Filter $selectedObjectId

        if (-not [string]::IsNullOrWhiteSpace($FlowName))
        {
            $route = "https://{flowEndpoint}/providers/Microsoft.ProcessSimple/environments/{environment}/flows/{flowName}/owners?api-version={apiVersion}'" `
            | ReplaceMacro -Macro "{flowName}" -Value $FlowName `
            | ReplaceMacro -Macro "{environment}" -Value $EnvironmentName;

            $flowRoleResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion

            foreach ($flowRole in $flowRoleResult.Value)
            {
                if (-not [string]::IsNullOrWhiteSpace($PrincipalObjectId))
                {
                    if ($pattern.IsMatch($flowRole.properties.principal.id))
                    {
                        CreateFlowRoleAssignmentObject -FlowRoleAssignmentObj $flowRole    
                    }
                }
                else 
                {    
                    CreateFlowRoleAssignmentObject -FlowRoleAssignmentObj $flowRole
                }
            }
        }
        else 
        {
            $flows = Get-Flow

            foreach($flow in $flows)
            {
                Get-FlowOwnerRole `
                    -FlowName $flow.FlowName `
                    -EnvironmentName $flow.EnvironmentName `
                    -PrincipalObjectId $selectedObjectId `
                    -ApiVersion $ApiVersion
            }
        }
    }
}

function Set-FlowOwnerRole
{
<#
 .SYNOPSIS
 sets owner permissions to the flow.
 .DESCRIPTION
 The Set-FlowOwnerRole set up permission to flow depending on parameters. 
 Use Get-Help Set-FlowOwnerRole -Examples for more detail.
 .PARAMETER EnvironmentName
 Limit app returned to those in a specified environment.
 .PARAMETER FlowName
 Specifies the flow id.
 .PARAMETER PrincipalType
 Specifies the type of principal that is being added as an owner; User or Group (security group)
 .PARAMETER PrincipalObjectId
 Specifies the principal object Id of the user or security group.
 .EXAMPLE
 Set-FlowOwnerRole -PrincipalType Group -PrincipalObjectId b049bf12-d56d-4b50-8176-c6560cbd35aa -FlowName 1ec3c80c-c2c0-4ea6-97a8-31d8c8c3d488 -EnvironmentName Default-55abc7e5-2812-4d73-9d2f-8d9017f8c877
 Add the specified security as an owner fo the flow with name 1ec3c80c-c2c0-4ea6-97a8-31d8c8c3d488 
 #> 
    [CmdletBinding(DefaultParameterSetName="User")]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$FlowName,

        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $true)]
        [ValidateSet("User", "Group")]
        [string]$PrincipalType,

        [Parameter(Mandatory = $true, ParameterSetName = "User")]
        [string]$PrincipalObjectId = $null,

        [Parameter(Mandatory = $false, ParameterSetName = "User")]
        [string]$ApiVersion = "2016-11-01"
    )
        
    process 
    {
        $userOrGroup = Get-UsersOrGroupsFromGraph -ObjectId $PrincipalObjectId
        $PrincipalDisplayName = $userOrGroup.DisplayName
        $PrincipalEmail = $userOrGroup.Mail


        $route = "https://{flowEndpoint}/providers/Microsoft.ProcessSimple/scopes/admin/environments/{environment}/flows/{flowName}/modifyowners?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{flowName}" -Value $FlowName `
        | ReplaceMacro -Macro "{environment}" -Value (ResolveEnvironment -OverrideId $EnvironmentName);

        #Construct the body 
        $requestbody = $null

        $requestbody = @{ 
            put = @(
                @{ 
                    properties = @{
                        principal = @{
                            email = $PrincipalEmail
                            id = $PrincipalObjectId
                            type = $PrincipalType
                            displayName = $PrincipalDisplayName
                        }         
                    }
                }
            )
        }

        $result = InvokeApi -Method POST -Route $route -Body $requestbody -ApiVersion $ApiVersion

        CreateHttpResponse($result)
    }
}

function Remove-FlowOwnerRole
{
<#
 .SYNOPSIS
 Removes owner permissions to the flow.
 .DESCRIPTION
 The Remove-FlowOwnerRole sets up permission to flow depending on parameters. 
 Use Get-Help Remove-FlowOwnerRole -Examples for more detail.
 .PARAMETER EnvironmentName
 The environment of the flow.
 .PARAMETER FlowName
 Specifies the flow id.
 .PARAMETER RoleId
 Specifies the role id of user or group or tenant.
 .EXAMPLE
 Remove-FlowOwnerRole -EnvironmentName "Default-55abc7e5-2812-4d73-9d2f-8d9017f8c877" -FlowName $flow.FlowName -RoleId "/providers/Microsoft.ProcessSimple/environments/Default-55abc7e5-2812-4d73-9d2f-8d9017f8c877/flows/791fc889-b9cc-4a76-9795-ae45f75d3e48/permissions/1ec3c80c-c2c0-4ea6-97a8-31d8c8c3d488"
 deletes flow permision for the given RoleId, FlowName and Environment name.
 #>
    [CmdletBinding(DefaultParameterSetName="Owner")]
    param
    (
        [Parameter(Mandatory = $false, ParameterSetName = "Owner")]
        [string]$ApiVersion = "2016-11-01",

        [Parameter(Mandatory = $true, ParameterSetName = "Owner", ValueFromPipelineByPropertyName = $true)]
        [string]$FlowName,

        [Parameter(Mandatory = $true, ParameterSetName = "Owner", ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $true, ParameterSetName = "Owner", ValueFromPipelineByPropertyName = $true)]
        [string]$RoleId
    )

    process
    {
        $route = "https://{flowEndpoint}/providers/Microsoft.ProcessSimple/environments/{environment}/flows/{flowName}/modifyPermissions?api-version={apiVersion}" `
            | ReplaceMacro -Macro "{flowName}" -Value $FlowName `
            | ReplaceMacro -Macro "{environment}" -Value (ResolveEnvironment -OverrideId $EnvironmentName);

        $requestbody = $null

        $requestbody = @{ 
            delete = @(
                @{ 
                    id = $RoleId
                    }
                )
                }

        $result = InvokeApi -Method POST -Route $route -Body $requestbody -ApiVersion $ApiVersion

        CreateHttpResponse($result)
    }
}

function Get-FlowRun
{
 <#
 .SYNOPSIS
 Gets flow run details for a specified flow.
 .DESCRIPTION
 The Get-FlowRun cmdlet retrieves flow execution history for a flow.
 .PARAMETER FlowName
 FlowName identifier (not display name).
  .PARAMETER EnvironmentName
 Limit flows returned to those in a specified environment.
 .EXAMPLE
 Get-FlowRun -FlowName cbb38ddd-c6a9-4ecd-8a70-aaaf448615df
 Retrieves flow run history for flow cbb38ddd-c6a9-4ecd-8a70-aaaf448615df
 #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [string]$FlowName,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2016-11-01"
    )

    process
    {
        $route = "https://{flowEndpoint}/providers/Microsoft.ProcessSimple/environments/{environmentName}/flows/{flowName}/runs?api-version={apiVersion}" `
            | ReplaceMacro -Macro "{flowName}" -Value $FlowName `
            | ReplaceMacro -Macro "{environmentName}" -Value (ResolveEnvironment -OverrideId $EnvironmentName);

        $runResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion
        foreach ($run in $runResult.Value)
        {
            CreateFlowRunObject -RunObj $run
        }
    }   
}

function Enable-Flow
{
 <#
 .SYNOPSIS
 Enables a flow
 .DESCRIPTION
 The Enable-Flow cmdlet enables a flow for execution. Use Get-Help Enable-Flow -Examples 
 for more detail.
 .PARAMETER FlowName
  FlowName identifier (not display name).
  .PARAMETER EnvironmentName
 Used to specify the environment of the Flow (if not the currently selected environment.)
 .EXAMPLE
 Enable-Flow -FlowName cbb38ddd-c6a9-4ecd-8a70-aaaf448615df
 Enables flow cbb38ddd-c6a9-4ecd-8a70-aaaf448615df for execution.
 #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [string]$FlowName,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2016-11-01"
    )

    process
    {
        $route = "https://{flowEndpoint}/providers/Microsoft.ProcessSimple/environments/{environmentName}/flows/{flowName}/start?api-version={apiVersion}" `
            | ReplaceMacro -Macro "{flowName}" -Value $FlowName `
            | ReplaceMacro -Macro "{environmentName}" -Value (ResolveEnvironment -OverrideId $EnvironmentName);

        InvokeApi -Method POST -Route $route -ApiVersion $ApiVersion
    }   
}

function Disable-Flow
{
 <#
 .SYNOPSIS
 Disables a flow
 .DESCRIPTION
 The Disable-Flow cmdlet disables a flow. Use Get-Help Disable-Flow -Examples 
 for more detail.
 .PARAMETER FlowId
 FlowId identifier (not display name).
 .PARAMETER EnvironmentName
 Used to specify the environment of the Flow (if not the currently selected environment.)
 .EXAMPLE
 Disable-Flow -FlowId cbb38ddd-c6a9-4ecd-8a70-aaaf448615df
 Disables flow cbb38ddd-c6a9-4ecd-8a70-aaaf448615df.
 #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [string]$FlowName,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2016-11-01"
    )

    process
    {
        $route = "https://{flowEndpoint}/providers/Microsoft.ProcessSimple/environments/{environmentName}/flows/{flowName}/stop?api-version={apiVersion}" `
            | ReplaceMacro -Macro "{flowName}" -Value $FlowName `
            | ReplaceMacro -Macro "{environmentName}" -Value (ResolveEnvironment -OverrideId $EnvironmentName);

        InvokeApi -Method POST -Route $route -ApiVersion $ApiVersion
    }  
}

function Remove-Flow
{
 <#
 .SYNOPSIS
 Removes a flow
 .DESCRIPTION
 The Remove-Flow cmdlet disables a flow. Use Get-Help Remove-Flow -Examples
 for more detail.
 .PARAMETER FlowId
 FlowId identifier (not display name).
 .PARAMETER EnvironmentName
 Used to specify the environment of the Flow (if not the currently selected environment.)
 .EXAMPLE
 Remove-Flow -FlowId cbb38ddd-c6a9-4ecd-8a70-aaaf448615df
 Deletes flow cbb38ddd-c6a9-4ecd-8a70-aaaf448615df.
 #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [string]$FlowName,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2016-11-01"
    )

    process
    {
        $route = "https://{flowEndpoint}/providers/Microsoft.ProcessSimple/environments/{environmentName}/flows/{flowName}?api-version={apiVersion}" `
            | ReplaceMacro -Macro "{flowName}" -Value $FlowName `
            | ReplaceMacro -Macro "{environmentName}" -Value (ResolveEnvironment -OverrideId $EnvironmentName);

        if ($PSCmdlet.ShouldProcess($FlowName, "Delete"))
        {
            InvokeApi -Method DELETE -Route $route -ApiVersion $ApiVersion
        }
    }
}

function Get-FlowApprovalRequest
{
 <#
 .SYNOPSIS
 Returns information about approval requests assigned to the current user
 .DESCRIPTION
 The Get-ApprovalRequest finds any pending received approval requests. 
 Use Get-Help Get-ApprovalRequest -Examples for more detail.
 .PARAMETER Filter
 Finds approvals matching the specified filter (wildcards supported).
 .PARAMETER Environment
 Limits approvals returned to the specified environment
 .PARAMETER Top
 Limits the result size of the query. Defaults to 50.
 .EXAMPLE
 Get-ApprovalRequest
 Finds all approvals assigned to the user in the current environment.
 .EXAMPLE
 Get-ApprovalRequest -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 Finds approval requests within the 3c2f7648-ad60-4871-91cb-b77d7ef3c239 environment
 .EXAMPLE
 Get-ApprovalRequest *Please review*
 Finds all approval requests that contain "Please review" 
 #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false, Position = 0)]
        [string[]]$Filter,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false)]
        [int]$Top = 50,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2016-11-01"
    )

    process
    {
        $currentEnvironment = ResolveEnvironment -OverrideId $EnvironmentName;

        $route = "https://{flowEndpoint}/providers/Microsoft.ProcessSimple/environments/{environmentName}/approvalRequests?api-version={apiVersion}&`$filter=properties/assignedTo/id eq '{currentUserId}'&`$expand=properties/approval" `
            | ReplaceMacro -Macro "{environmentName}" -Value $currentEnvironment `
            | ReplaceMacro -Macro "{currentUserId}" -Value $global:currentSession.UserId `
            | ReplaceMacro -Macro "{topValue}" -Value $Top.ToString();

        $approvalRequests = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion
        $pattern = BuildFilterPattern -Filter $Filter;

        foreach ($approval in $approvalRequests.Value)
        {
            if ($pattern.IsMatch($approval.name) -or
                $pattern.IsMatch($approval.properties.approval.title))
            {
                CreateApprovalRequestObject -ApprovalRequest $approval -Environment $currentEnvironment
            }
        }
    }
}

function Get-FlowApproval
{
 <#
 .SYNOPSIS
 Returns information about approval requests created by the current user
 .DESCRIPTION
 The Get-Approval finds any pending sent approval requests. 
 Use Get-Help Get-Approval -Examples for more detail.
 .PARAMETER Filter
 Finds approvals matching the specified filter (wildcards supported).
 .PARAMETER EnvironmentName
 Limits approvals returned to the specified environment
 .PARAMETER Top
 Limits the result size of the query. Defaults to 50.
 .EXAMPLE
 Get-Approval
 Finds all approvals created by the current user in the current environment.
 .EXAMPLE
 Get-Approval -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 Finds approval within the 3c2f7648-ad60-4871-91cb-b77d7ef3c239 environment
 .EXAMPLE
 Get-Approval *Please review*
 Finds all approval requests that contain "Please review" 
 #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false, Position = 0)]
        [string[]]$Filter,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false)]
        [int]$Top = 50,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2016-11-01"
    )

    process
    {
        $currentEnvironment = ResolveEnvironment -OverrideId $EnvironmentName;

        $route = "https://{flowEndpoint}/providers/Microsoft.ProcessSimple/environments/{environmentName}/approvals?api-version={apiVersion}&`$filter=properties/owner/id eq '{currentUserId}' and properties/status eq 'Pending'&`$expand=properties/requestSummary" `
            | ReplaceMacro -Macro "{environmentName}" -Value $currentEnvironment `
            | ReplaceMacro -Macro "{currentUserId}" -Value $global:currentSession.UserId `
            | ReplaceMacro -Macro "{topValue}" -Value $Top.ToString();

        $approvals = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion
        $pattern = BuildFilterPattern -Filter $Filter;

        foreach ($approval in $approvals.Value)
        {
            if ($pattern.IsMatch($approval.name) -or
                $pattern.IsMatch($approval.properties.approval.title))
            {
                CreateApprovalObject -Approval $approval -Environment $currentEnvironment
            }
        }
    }
}

function RespondTo-FlowApprovalRequest
{
 <#
 .SYNOPSIS
 Approve or reject an approval response
 .DESCRIPTION
 The RespondTo-FlowApprovalRequest cmdlet to approval or reject a request 
 Use Get-Help RespondTo-FlowApprovalRequest -Examples for more detail.
 .PARAMETER ApprovalId
 Id of the approval for which the user is responding.
 .PARAMETER ApprovalRequestId
 Id of the user's request for the approval.
 .PARAMETER EnvironmentName
 Environment containing the specified approval
 .PARAMETER Response
 The response. Must be "Approve" or "Reject"
 .PARAMETER Comments
 Comments to attach to the response.
 .EXAMPLE
 RespondTo-FlowApprovalRequest -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239 -ApprovalId d5f65cd7-7c10-41b6-aa93-68a145bb64e7 -ApprovalRequestId 94be632a-83d1-499e-8e65-d6e0e7c2cb1a -Response "Reject" -Comments "no response"
 Rejects a specific approval within the 3c2f7648-ad60-4871-91cb-b77d7ef3c239 environment
 .EXAMPLE
 Get-FlowApprovalRequest | ? { $_.Owner -eq 'joe@contoso.com' } | RespondTo-ApprovalRequest -Response "Approve" -Comments "looks good"
 Finds all approval requests that contain "Please review" and approves them
 #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$ApprovalId,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$ApprovalRequestId,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Approve", "Reject")]
        [string]$Response,

        [Parameter(Mandatory = $true)]
        [string]$Comments,
        
        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2016-11-01"
    )

    process
    {
        $currentEnvironment = ResolveEnvironment -OverrideId $EnvironmentName

        $approvalResponse = BuildApprovalResponse `
            -EnvironmentName $currentEnvironment `
            -ApprovalId $ApprovalId `
            -ApprovalRequestId $ApprovalRequestId `
            -Response $Response `
            -Comments $Comments

        $route = "https://{flowEndpoint}/providers/Microsoft.ProcessSimple/environments/{environmentName}/approvals/{approvalId}/approvalResponses?api-version={apiVersion}" `
            | ReplaceMacro -Macro "{environmentName}" -Value $currentEnvironment `
            | ReplaceMacro -Macro "{approvalId}" -Value $ApprovalId;

        $ignored = InvokeApi -Method POST -Route $route -Body $approvalResponse -ApiVersion $apiVersion
    }
}


#internal, helper function
function Get-FilteredEnvironments(
)
{
     param
    (
        [Parameter(Mandatory = $false)]
        [object]$Filter,

        [Parameter(Mandatory = $false)]
        [object]$CreatedBy,

        [Parameter(Mandatory = $false)]
        [object]$EnvironmentResult
    )

    $patternOwner = BuildFilterPattern -Filter $CreatedBy
    $patternFilter = BuildFilterPattern -Filter $Filter
            
    foreach ($env in $EnvironmentResult.Value)
    {
        if ($patternOwner.IsMatch($env.properties.createdBy.displayName) -or
            $patternOwner.IsMatch($env.properties.createdBy.email) -or 
            $patternOwner.IsMatch($env.properties.createdBy.id) -or 
            $patternOwner.IsMatch($env.properties.createdBy.userPrincipalName))
        {
            if ($patternFilter.IsMatch($env.name) -or
                $patternFilter.IsMatch($env.properties.displayName))
            {
                CreateEnvironmentObject -EnvObject $env
            }
        }
    }
}

#internal, helper function
function CreateAppObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$AppObj
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name AppName -Value $AppObj.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name DisplayName -Value $AppObj.properties.displayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name CreatedTime -Value $AppObj.properties.createdTime `
        | Add-Member -PassThru -MemberType NoteProperty -Name LastModifiedTime -Value $AppObj.properties.lastModifiedTime `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $AppObj.properties.environment.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name UnpublishedAppDefinition -Value $AppObj.properties.unpublishedAppDefinition `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $AppObj;
}

#internal, helper function
function CreateConnectionObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$ConnectionObj
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name ConnectionName -Value $ConnectionObj.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name ConnectionId -Value $ConnectionObj.id `
        | Add-Member -PassThru -MemberType NoteProperty -Name FullConnectorName -Value $ConnectionObj.properties.apiId `
        | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorName -Value ((($ConnectionObj.properties.apiId -split "/apis/")[1]) -split "/")[0] `
        | Add-Member -PassThru -MemberType NoteProperty -Name DisplayName -Value $ConnectionObj.properties.displayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name CreatedTime -Value $ConnectionObj.properties.createdTime `
        | Add-Member -PassThru -MemberType NoteProperty -Name CreatedBy -Value $ConnectionObj.properties.createdBy `
        | Add-Member -PassThru -MemberType NoteProperty -Name LastModifiedTime -Value $ConnectionObj.properties.lastModifiedTime `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $ConnectionObj.properties.environment.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name Statuses -Value $ConnectionObj.properties.statuses `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $ConnectionObj;
}

#internal, helper function
function CreateConnectionRoleAssignmentObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$ConnectionRoleAssignmentObj,

        [Parameter(Mandatory = $false)]
        [string]$EnvironmentName
    )

    If($ConnectionRoleAssignmentObj.properties.principal.type -eq "Tenant")
    {
        return New-Object -TypeName PSObject `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleId -Value $ConnectionRoleAssignmentObj.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleName -Value $ConnectionRoleAssignmentObj.name `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalDisplayName -Value $null `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalEmail -Value $null `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalObjectId -Value $ConnectionRoleAssignmentObj.properties.principal.tenantId `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalType -Value $ConnectionRoleAssignmentObj.properties.principal.type `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleType -Value $ConnectionRoleAssignmentObj.properties.roleName `
            | Add-Member -PassThru -MemberType NoteProperty -Name ConnectionName -Value ((($ConnectionRoleAssignmentObj.id -split "/connections/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorName -Value ((($ConnectionRoleAssignmentObj.id -split "/apis/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $EnvironmentName `
            | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $ConnectionRoleAssignmentObj;
    }
    elseif($ConnectionRoleAssignmentObj.properties.principal.type -eq "User")
    {
        return New-Object -TypeName PSObject `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleId -Value $ConnectionRoleAssignmentObj.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleName -Value $ConnectionRoleAssignmentObj.name `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalDisplayName -Value $ConnectionRoleAssignmentObj.properties.principal.displayName `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalEmail -Value $ConnectionRoleAssignmentObj.properties.principal.email `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalObjectId -Value $ConnectionRoleAssignmentObj.properties.principal.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalType -Value $ConnectionRoleAssignmentObj.properties.principal.type `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleType -Value $ConnectionRoleAssignmentObj.properties.roleName `
            | Add-Member -PassThru -MemberType NoteProperty -Name ConnectionName -Value ((($ConnectionRoleAssignmentObj.id -split "/connections/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorName -Value ((($ConnectionRoleAssignmentObj.id -split "/apis/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $EnvironmentName `
            | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $ConnectionRoleAssignmentObj;
    }
    elseif($ConnectionRoleAssignmentObj.properties.principal.type -eq "Group")
    {
        return New-Object -TypeName PSObject `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleId -Value $ConnectionRoleAssignmentObj.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleName -Value $ConnectionRoleAssignmentObj.name `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalDisplayName -Value $ConnectionRoleAssignmentObj.properties.principal.displayName `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalEmail -Value $null `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalObjectId -Value $ConnectionRoleAssignmentObj.properties.principal.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalType -Value $ConnectionRoleAssignmentObj.properties.principal.type `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleType -Value $ConnectionRoleAssignmentObj.properties.roleName `
            | Add-Member -PassThru -MemberType NoteProperty -Name ConnectionName -Value ((($ConnectionRoleAssignmentObj.id -split "/permission/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorName -Value ((($ConnectionRoleAssignmentObj.id -split "/apis/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $EnvironmentName `
            | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $ConnectionRoleAssignmentObj;
    }
    else {
        return $null
    }
}

#internal, helper function
function CreateConnectorObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$ConnectorObj,

        [Parameter(Mandatory = $false)]
        [string]$EnvironmentName
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorName -Value $ConnectorObj.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorId -Value $ConnectorObj.id `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $EnvironmentName `
        | Add-Member -PassThru -MemberType NoteProperty -Name CreatedTime -Value $ConnectorObj.properties.createdTime `
        | Add-Member -PassThru -MemberType NoteProperty -Name ChangedTime -Value $ConnectorObj.properties.changedtime `
        | Add-Member -PassThru -MemberType NoteProperty -Name DisplayName -Value $ConnectorObj.properties.displayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name Description -Value $ConnectorObj.properties.description `
        | Add-Member -PassThru -MemberType NoteProperty -Name Publisher -Value $ConnectorObj.properties.publisher `
        | Add-Member -PassThru -MemberType NoteProperty -Name Source -Value $ConnectorObj.properties.metadata.source `
        | Add-Member -PassThru -MemberType NoteProperty -Name Tier -Value $ConnectorObj.properties.tier `
        | Add-Member -PassThru -MemberType NoteProperty -Name Url -Value $ConnectorObj.properties.primaryRuntimeUrl `
        | Add-Member -PassThru -MemberType NoteProperty -Name ConnectionParameters -Value $ConnectorObj.properties.connectionParameters `
        | Add-Member -PassThru -MemberType NoteProperty -Name Swagger -Value $ConnectorObj.properties.swagger `
        | Add-Member -PassThru -MemberType NoteProperty -Name WadlUrl -Value $ConnectorObj.properties.wadlUrl `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $ConnectorObj;
}

#internal, helper function
function CreateConnectorRoleAssignmentObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$ConnectorRoleAssignmentObj,

        [Parameter(Mandatory = $false)]
        [string]$EnvironmentName
    )

    If($ConnectorRoleAssignmentObj.properties.principal.type -eq "Tenant")
    {
        return New-Object -TypeName PSObject `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleId -Value $ConnectorRoleAssignmentObj.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleName -Value $ConnectorRoleAssignmentObj.name `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalDisplayName -Value $null `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalEmail -Value $null `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalObjectId -Value $ConnectorRoleAssignmentObj.properties.principal.tenantId `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalType -Value $ConnectorRoleAssignmentObj.properties.principal.type `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleType -Value $ConnectorRoleAssignmentObj.properties.roleName `
            | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorName -Value ((($ConnectorRoleAssignmentObj.id -split "/apis/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $EnvironmentName `
            | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $ConnectorRoleAssignmentObj;
    }
    elseif($ConnectorRoleAssignmentObj.properties.principal.type -eq "User")
    {
        return New-Object -TypeName PSObject `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleId -Value $ConnectorRoleAssignmentObj.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleName -Value $ConnectorRoleAssignmentObj.name `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalDisplayName -Value $ConnectorRoleAssignmentObj.properties.principal.displayName `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalEmail -Value $ConnectorRoleAssignmentObj.properties.principal.email `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalObjectId -Value $ConnectorRoleAssignmentObj.properties.principal.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalType -Value $ConnectorRoleAssignmentObj.properties.principal.type `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleType -Value $ConnectorRoleAssignmentObj.properties.roleName `
            | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorName -Value ((($ConnectorRoleAssignmentObj.id -split "/apis/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $EnvironmentName `
            | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $ConnectorRoleAssignmentObj;
    }
    elseif($ConnectorRoleAssignmentObj.properties.principal.type -eq "Group")
    {
        return New-Object -TypeName PSObject `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleId -Value $ConnectorRoleAssignmentObj.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleName -Value $ConnectorRoleAssignmentObj.name `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalDisplayName -Value $ConnectorRoleAssignmentObj.properties.principal.displayName `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalEmail -Value $null `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalObjectId -Value $ConnectorRoleAssignmentObj.properties.principal.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalType -Value $ConnectorRoleAssignmentObj.properties.principal.type `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleType -Value $ConnectorRoleAssignmentObj.properties.roleName `
            | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorName -Value ((($ConnectorRoleAssignmentObj.id -split "/apis/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $EnvironmentName `
            | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $ConnectorRoleAssignmentObj;
    }
    else {
        return $null
    }
}

#internal, helper function
function CreateAppVersionObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$AppVersionObj
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name AppVersionName -Value $AppVersionObj.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name CreatedTime -Value $AppVersionObj.properties.appVersion `
        | Add-Member -PassThru -MemberType NoteProperty -Name LifecycleId -Value $AppVersionObj.properties.lifeCycleId `
        | Add-Member -PassThru -MemberType NoteProperty -Name PowerAppsRelease -Value (($AppVersionObj.properties.createdByClientVersion.major).ToString() + "." + ($AppVersionObj.properties.createdByClientVersion.minor).ToString() + "." + ($AppVersionObj.properties.createdByClientVersion.build).ToString())`
        | Add-Member -PassThru -MemberType NoteProperty -Name AppName -Value $AppVersionObj.properties.appName `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $AppVersionObj;
}

#internal, helper function
function CreateAppRoleAssignmentObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$AppRoleAssignmentObj
    )

    If($AppRoleAssignmentObj.properties.principal.type -eq "Tenant")
    {
        return New-Object -TypeName PSObject `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleId -Value $AppRoleAssignmentObj.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleName -Value $AppRoleAssignmentObj.name `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalDisplayName -Value $null `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalEmail -Value $null `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalObjectId -Value $AppRoleAssignmentObj.properties.principal.tenantId `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalType -Value $AppRoleAssignmentObj.properties.principal.type `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleType -Value $AppRoleAssignmentObj.properties.roleName `
            | Add-Member -PassThru -MemberType NoteProperty -Name AppName -Value ((($AppRoleAssignmentObj.properties.scope -split "/apps/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value ((($AppRoleAssignmentObj.properties.scope -split "/environments/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $AppRoleAssignmentObj;
    }
    elseif($AppRoleAssignmentObj.properties.principal.type -eq "User")
    {
        return New-Object -TypeName PSObject `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleId -Value $AppRoleAssignmentObj.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleName -Value $AppRoleAssignmentObj.name `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalDisplayName -Value $AppRoleAssignmentObj.properties.principal.displayName `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalEmail -Value $AppRoleAssignmentObj.properties.principal.email `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalObjectId -Value $AppRoleAssignmentObj.properties.principal.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalType -Value $AppRoleAssignmentObj.properties.principal.type `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleType -Value $AppRoleAssignmentObj.properties.roleName `
            | Add-Member -PassThru -MemberType NoteProperty -Name AppName -Value ((($AppRoleAssignmentObj.properties.scope -split "/apps/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value ((($AppRoleAssignmentObj.properties.scope -split "/environments/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $AppRoleAssignmentObj;
    }
    elseif($AppRoleAssignmentObj.properties.principal.type -eq "Group")
    {
        return New-Object -TypeName PSObject `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleId -Value $AppRoleAssignmentObj.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleName -Value $AppRoleAssignmentObj.name `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalDisplayName -Value $AppRoleAssignmentObj.properties.principal.displayName `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalEmail -Value $null `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalObjectId -Value $AppRoleAssignmentObj.properties.principal.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalType -Value $AppRoleAssignmentObj.properties.principal.type `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleType -Value $AppRoleAssignmentObj.properties.roleName `
            | Add-Member -PassThru -MemberType NoteProperty -Name AppName -Value ((($AppRoleAssignmentObj.properties.scope -split "/apps/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value ((($AppRoleAssignmentObj.properties.scope -split "/environments/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $AppRoleAssignmentObj;
    }
    else {
        return $null
    }
}

#internal, helper function
function CreatePowerAppsNotificationObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$PowerAppsNotificationObj
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name AppVersionName -Value $PowerAppsNotificationObj.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name PowerAppsNotificationId -Value $PowerAppsNotificationObj.id `
        | Add-Member -PassThru -MemberType NoteProperty -Name PowerAppsNotificationName -Value $PowerAppsNotificationObj.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name Category -Value $PowerAppsNotificationObj.properties.category `
        | Add-Member -PassThru -MemberType NoteProperty -Name Content -Value $PowerAppsNotificationObj.properties.content `
        | Add-Member -PassThru -MemberType NoteProperty -Name CreatedTime -Value $PowerAppsNotificationObj.properties.createdTime `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $PowerAppsNotificationObj;
}

#internal, helper function
function CreateFlowObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$FlowObj
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name FlowName -Value $FlowObj.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name Enabled -Value ($FlowObj.properties.state -eq 'Started') `
        | Add-Member -PassThru -MemberType NoteProperty -Name DisplayName -Value $FlowObj.properties.displayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name UserType -Value $FlowObj.properties.userType `
        | Add-Member -PassThru -MemberType NoteProperty -Name CreatedTime -Value $FlowObj.properties.createdTime `
        | Add-Member -PassThru -MemberType NoteProperty -Name LastModifiedTime -Value $FlowObj.properties.lastModifiedTime `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $FlowObj.properties.environment.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $FlowObj;
}
#internal, helper function
function CreateFlowRoleAssignmentObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$FlowRoleAssignmentObj
    )
        
    if($FlowRoleAssignmentObj.properties.principal.type -eq "User")
    {
        return New-Object -TypeName PSObject `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleId -Value $FlowRoleAssignmentObj.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleName -Value $FlowRoleAssignmentObj.name `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalObjectId -Value $FlowRoleAssignmentObj.properties.principal.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalType -Value $FlowRoleAssignmentObj.properties.principal.type `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleType -Value $FlowRoleAssignmentObj.properties.roleName `
            | Add-Member -PassThru -MemberType NoteProperty -Name FlowName -Value ((($FlowRoleAssignmentObj.id -split "/flows/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value ((($FlowRoleAssignmentObj.id -split "/environments/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $FlowRoleAssignmentObj;
    }
    elseif($FlowRoleAssignmentObj.properties.principal.type -eq "Group")
    {
        return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name RoleId -Value $FlowRoleAssignmentObj.id `
        | Add-Member -PassThru -MemberType NoteProperty -Name RoleName -Value $FlowRoleAssignmentObj.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalObjectId -Value $FlowRoleAssignmentObj.properties.principal.id `
        | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalType -Value $FlowRoleAssignmentObj.properties.principal.type `
        | Add-Member -PassThru -MemberType NoteProperty -Name RoleType -Value $FlowRoleAssignmentObj.properties.roleName `
        | Add-Member -PassThru -MemberType NoteProperty -Name FlowName -Value ((($FlowRoleAssignmentObj.id -split "/flows/")[1]) -split "/")[0] `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value ((($FlowRoleAssignmentObj.id -split "/environments/")[1]) -split "/")[0] `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $FlowRoleAssignmentObj;
    }
    else {
        return $null
    }
}

#internal, helper function
function CreateFlowRunObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$RunObj
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name FlowRunName -Value $RunObj.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name Status -Value $RunObj.properties.status `
        | Add-Member -PassThru -MemberType NoteProperty -Name StartTime -Value $RunObj.properties.startTime `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $RunObj;
}

#internal, helper function
function CreateEnvironmentObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$EnvObject
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $EnvObject.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name DisplayName -Value $EnvObject.properties.displayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name IsDefault -Value $EnvObject.properties.isDefault `
        | Add-Member -PassThru -MemberType NoteProperty -Name Location -Value $EnvObject.location `
        | Add-Member -PassThru -MemberType NoteProperty -Name CreatedTime -Value $EnvObject.properties.createdTime `
        | Add-Member -PassThru -MemberType NoteProperty -Name CreatedBy -value $EnvObject.properties.createdBy.userPrincipalName `
        | Add-Member -PassThru -MemberType NoteProperty -Name LastModifiedTime -Value $EnvObject.properties.lastModifiedTime `
        | Add-Member -PassThru -MemberType NoteProperty -Name LastModifiedBy -value $EnvObject.properties.lastModifiedBy.userPrincipalName `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -value $EnvObject;
}

#internal, helper function
function CreateApprovalRequestObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$ApprovalRequest,

        [Parameter(Mandatory = $true)]
        [string]$EnvironmentName
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name ApprovalRequestId -Value $ApprovalRequest.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name Title -Value $ApprovalRequest.properties.approval.properties.title `
        | Add-Member -PassThru -MemberType NoteProperty -Name Details -Value $ApprovalRequest.properties.approval.properties.details `
        | Add-Member -PassThru -MemberType NoteProperty -Name ApprovalId -Value $ApprovalRequest.properties.approval.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name Owner -Value $ApprovalRequest.properties.approval.properties.owner.userPrincipalName `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $EnvironmentName `
        | Add-Member -PassThru -MemberType NoteProperty -Name CreationDate -Value $ApprovalRequest.properties.approval.properties.creationDate `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $ApprovalRequest
}

#internal, helper function
function CreateApprovalObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$Approval,

        [Parameter(Mandatory = $true)]
        [string]$EnvironmentName
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name ApprovalId -Value $Approval.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name Title -Value $Approval.properties.title `
        | Add-Member -PassThru -MemberType NoteProperty -Name Details -Value $Approval.properties.details `
        | Add-member -PassThru -MemberType NoteProperty -Name AssignedTo -Value ($Approval.properties.requestSummary.approvers | select userPrincipalName) `
        | Add-Member -PassThru -MemberType NoteProperty -Name CreationDate -Value $Approval.properties.creationDate `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $EnvironmentName `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $Approval
}

#internal, helper function
function BuildApprovalResponse
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $true)]
        [string]$ApprovalId,

        [Parameter(Mandatory = $true)]
        [string]$ApprovalRequestId,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Approve", "Reject")]
        [string]$Response,

        [Parameter(Mandatory = $true)]
        [string]$Comments
    )

    $owner = New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name id -Value $global:currentSession.userId `
        | Add-Member -PassThru -MemberType NoteProperty -Name type -Value "NotSpecified" `
        | Add-Member -PassThru -MemberType NoteProperty -Name tenantId $global:currentSession.tenantId

    $properties = New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name stage -Value "Basic" `
        | Add-Member -PassThru -MemberType NoteProperty -Name status -Value "Committed" `
        | Add-Member -PassThru -MemberType NoteProperty -Name creationDate -Value ([DateTime]::UtcNow.ToString("o")) `
        | Add-Member -PassThru -MemberType NoteProperty -Name owner -Value $owner `
        | Add-Member -PassThru -MemberType NoteProperty -Name response -Value $Response `
        | Add-Member -PassThru -MemberType NoteProperty -Name comments -Value $Comments

    $approvalResponse = New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name name -Value $ApprovalRequestId `
        | Add-Member -PassThru -MemberType NoteProperty -Name id -Value "/providers/Microsoft.ProcessSimple/environments/$EnvironmentName/approvals/$ApprovalId/approvalResponses/$ApprovalRequestId" `
        | Add-Member -PassThru -MemberType NoteProperty -Name type -Value "/providers/Microsoft.ProcessSimple/environments/approvals/approvalResponses" `
        | Add-Member -PassThru -MemberType NoteProperty -Name properties -Value $properties
        
    return $approvalResponse
}


#internal, helper function
function CreateHttpResponse
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$ResponseObject
    )
    
    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name Code -Value $ResponseObject.StatusCode `
        | Add-Member -PassThru -MemberType NoteProperty -Name Description -Value $ResponseObject.StatusDescription `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -value $ResponseObject;
}
# SIG # Begin signature block
# MIItNAYJKoZIhvcNAQcCoIItJTCCLSECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBjw6limrbv4m12
# SivIqb7NMSlWyMM8pHDhNff8J76YP6CCEWQwggh2MIIHXqADAgECAhM2AAAAh2rh
# X7Bvfrt0AAEAAACHMA0GCSqGSIb3DQEBCwUAMEExEzARBgoJkiaJk/IsZAEZFgNH
# QkwxEzARBgoJkiaJk/IsZAEZFgNBTUUxFTATBgNVBAMTDEFNRSBDUyBDQSAwMTAe
# Fw0xODA3MTAxMzA4NDlaFw0xOTA3MTAxMzA4NDlaMC8xLTArBgNVBAMTJE1pY3Jv
# c29mdCBBenVyZSBEZXBlbmRlbmN5IENvZGUgU2lnbjCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAPf3/ZREq1xrUwIv3rE+B+9hgWu6A+9pATQBXADzJ1qA
# hxEKwDgBnpI3w4my/XssamM1SXZ1Ly/RqiAhbBnWiu57Mak5zIctiVAoH+JIliQD
# 2F8CO+K1drdj+V+MouJnlhYFYw5zEjJxk8gQVXBj+VlEcIVPBd+FBpuhAfWGHC/8
# NZYS779+HrCG1i5qGBpVEFK0Yx9shdJ3wBVWD0L4ZziltKV3oOdjysJ8rL8iL/Ig
# DcIlmcb4BnL0th/MAJLUTBxWRyUxKYyolabZIExXia3DmNz2EFmKpix7URu7eVQM
# SgAMXtUdWmaX5vJPYEXFBszAwI2Kq3cs85EJSFUWJB8CAwEAAaOCBXcwggVzMCkG
# CSsGAQQBgjcVCgQcMBowDAYKKwYBBAGCN1sDATAKBggrBgEFBQcDAzA8BgkrBgEE
# AYI3FQcELzAtBiUrBgEEAYI3FQiGkOMNhNW0eITxiz6Fm90Wzp0SgWDigi2HkK4D
# AgFkAgENMIICdgYIKwYBBQUHAQEEggJoMIICZDBiBggrBgEFBQcwAoZWaHR0cDov
# L2NybC5taWNyb3NvZnQuY29tL3BraWluZnJhL0NlcnRzL0JZMlBLSUNTQ0EwMS5B
# TUUuR0JMX0FNRSUyMENTJTIwQ0ElMjAwMSgxKS5jcnQwUgYIKwYBBQUHMAKGRmh0
# dHA6Ly9jcmwxLmFtZS5nYmwvYWlhL0JZMlBLSUNTQ0EwMS5BTUUuR0JMX0FNRSUy
# MENTJTIwQ0ElMjAwMSgxKS5jcnQwUgYIKwYBBQUHMAKGRmh0dHA6Ly9jcmwyLmFt
# ZS5nYmwvYWlhL0JZMlBLSUNTQ0EwMS5BTUUuR0JMX0FNRSUyMENTJTIwQ0ElMjAw
# MSgxKS5jcnQwUgYIKwYBBQUHMAKGRmh0dHA6Ly9jcmwzLmFtZS5nYmwvYWlhL0JZ
# MlBLSUNTQ0EwMS5BTUUuR0JMX0FNRSUyMENTJTIwQ0ElMjAwMSgxKS5jcnQwUgYI
# KwYBBQUHMAKGRmh0dHA6Ly9jcmw0LmFtZS5nYmwvYWlhL0JZMlBLSUNTQ0EwMS5B
# TUUuR0JMX0FNRSUyMENTJTIwQ0ElMjAwMSgxKS5jcnQwga0GCCsGAQUFBzAChoGg
# bGRhcDovLy9DTj1BTUUlMjBDUyUyMENBJTIwMDEsQ049QUlBLENOPVB1YmxpYyUy
# MEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9
# QU1FLERDPUdCTD9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlm
# aWNhdGlvbkF1dGhvcml0eTAdBgNVHQ4EFgQULZktR9nSbfs0Ys9sqwYAWWCZPxsw
# DgYDVR0PAQH/BAQDAgeAMEUGA1UdEQQ+MDykOjA4MR4wHAYDVQQLExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xFjAUBgNVBAUTDTIzNjE2OSs0MzgwNDcwggHUBgNVHR8E
# ggHLMIIBxzCCAcOgggG/oIIBu4Y8aHR0cDovL2NybC5taWNyb3NvZnQuY29tL3Br
# aWluZnJhL0NSTC9BTUUlMjBDUyUyMENBJTIwMDEuY3Jshi5odHRwOi8vY3JsMS5h
# bWUuZ2JsL2NybC9BTUUlMjBDUyUyMENBJTIwMDEuY3Jshi5odHRwOi8vY3JsMi5h
# bWUuZ2JsL2NybC9BTUUlMjBDUyUyMENBJTIwMDEuY3Jshi5odHRwOi8vY3JsMy5h
# bWUuZ2JsL2NybC9BTUUlMjBDUyUyMENBJTIwMDEuY3Jshi5odHRwOi8vY3JsNC5h
# bWUuZ2JsL2NybC9BTUUlMjBDUyUyMENBJTIwMDEuY3JshoG6bGRhcDovLy9DTj1B
# TUUlMjBDUyUyMENBJTIwMDEsQ049QlkyUEtJQ1NDQTAxLENOPUNEUCxDTj1QdWJs
# aWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9u
# LERDPUFNRSxEQz1HQkw/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29i
# amVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MB8GA1UdIwQYMBaAFBtmohn8
# m+ul2oSPGJjpEKTDe5K9MB8GA1UdJQQYMBYGCisGAQQBgjdbAwEGCCsGAQUFBwMD
# MA0GCSqGSIb3DQEBCwUAA4IBAQDPWYN9t5RNknehD6HG/lGEJokcOcgxiCw5kMen
# fHjsQzVonpYznweZUGuy/yvR4FqCKejkJe38NFLB156IeV2RZwl8J5BBeM093b8c
# b4fWdPmAOixP43wFSKy4WHJKcpohSHCT/g5+nfwUP6/BYx0fqGKoISbJW6fyJ9NI
# gTBYkJ9g2awJg3dLRvRXeV53WONNBu1KrgJ9Ne6Yo1fKUI6VBUmS5fL3B0VbkUn1
# JdeP1H0exAV+Qk3mkfC0r28APVQ49i1gcc+rFaWc76bRZyj1lfBXZP3UVbLN6iDF
# G7NHSzlh15r4TgAuf8zKQklUhE30ZQc+24DFcoK0Gar3JX7IMIII5jCCBs6gAwIB
# AgITHwAAABS0xR/G8oC+cQAAAAAAFDANBgkqhkiG9w0BAQsFADA8MRMwEQYKCZIm
# iZPyLGQBGRYDR0JMMRMwEQYKCZImiZPyLGQBGRYDQU1FMRAwDgYDVQQDEwdhbWVy
# b290MB4XDTE2MDkxNTIxMzMwM1oXDTIxMDkxNTIxNDMwM1owQTETMBEGCgmSJomT
# 8ixkARkWA0dCTDETMBEGCgmSJomT8ixkARkWA0FNRTEVMBMGA1UEAxMMQU1FIENT
# IENBIDAxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1VeBAtb5+tD3
# G4C53TfNJNxmYfzhiXKtKQzSGxuav660bTS1VEeDDjSnFhsmnlb6GkPCeYmCJwWg
# ZGs+3oWJ8yad3//VoP99bXG8azzTJmT2PFM1yKxUXUJgi7I9y3C4ll/ATfBwbGGR
# XD+2PdkdlVpxKWzeNEPVwbCtxWjUhHr6Ecy9R6O23j+2/RSZSgfzYctDzDWhNf0P
# vGPflm31PSk4+ozca337/Ozu0+naDKg5i/zFHhfSJZkq5dPPG6C8wDrdiwHh6G5I
# GrMd2QXnmvEfjtpPqE+G8MeWbszaWxlxEjQJQC6PBwn+8Qt4Vqlc0am3Z3fBw8kz
# RunOs8Mn/wIDAQABo4IE2jCCBNYwEAYJKwYBBAGCNxUBBAMCAQEwIwYJKwYBBAGC
# NxUCBBYEFJH8M85CnvaT5uJ9VNcIGLu413FlMB0GA1UdDgQWBBQbZqIZ/JvrpdqE
# jxiY6RCkw3uSvTCCAQQGA1UdJQSB/DCB+QYHKwYBBQIDBQYIKwYBBQUHAwEGCCsG
# AQUFBwMCBgorBgEEAYI3FAIBBgkrBgEEAYI3FQYGCisGAQQBgjcKAwwGCSsGAQQB
# gjcVBgYIKwYBBQUHAwkGCCsGAQUFCAICBgorBgEEAYI3QAEBBgsrBgEEAYI3CgME
# AQYKKwYBBAGCNwoDBAYJKwYBBAGCNxUFBgorBgEEAYI3FAICBgorBgEEAYI3FAID
# BggrBgEFBQcDAwYKKwYBBAGCN1sBAQYKKwYBBAGCN1sCAQYKKwYBBAGCN1sDAQYK
# KwYBBAGCN1sFAQYKKwYBBAGCN1sEAQYKKwYBBAGCN1sEAjAZBgkrBgEEAYI3FAIE
# DB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADAf
# BgNVHSMEGDAWgBQpXlFeZK40ueusnA2njHUB0QkLKDCCAWgGA1UdHwSCAV8wggFb
# MIIBV6CCAVOgggFPhiNodHRwOi8vY3JsMS5hbWUuZ2JsL2NybC9hbWVyb290LmNy
# bIYxaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraWluZnJhL2NybC9hbWVyb290
# LmNybIYjaHR0cDovL2NybDIuYW1lLmdibC9jcmwvYW1lcm9vdC5jcmyGI2h0dHA6
# Ly9jcmwzLmFtZS5nYmwvY3JsL2FtZXJvb3QuY3JshoGqbGRhcDovLy9DTj1hbWVy
# b290LENOPUFNRVJPT1QsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2Vz
# LENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9QU1FLERDPUdCTD9jZXJ0
# aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJp
# YnV0aW9uUG9pbnQwggGrBggrBgEFBQcBAQSCAZ0wggGZMDcGCCsGAQUFBzAChito
# dHRwOi8vY3JsMS5hbWUuZ2JsL2FpYS9BTUVST09UX2FtZXJvb3QuY3J0MEcGCCsG
# AQUFBzAChjtodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpaW5mcmEvY2VydHMv
# QU1FUk9PVF9hbWVyb290LmNydDA3BggrBgEFBQcwAoYraHR0cDovL2NybDIuYW1l
# LmdibC9haWEvQU1FUk9PVF9hbWVyb290LmNydDA3BggrBgEFBQcwAoYraHR0cDov
# L2NybDMuYW1lLmdibC9haWEvQU1FUk9PVF9hbWVyb290LmNydDCBogYIKwYBBQUH
# MAKGgZVsZGFwOi8vL0NOPWFtZXJvb3QsQ049QUlBLENOPVB1YmxpYyUyMEtleSUy
# MFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9QU1FLERD
# PUdCTD9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlv
# bkF1dGhvcml0eTANBgkqhkiG9w0BAQsFAAOCAgEAKLdKhpqPH6QBaM3CAOqQi8oA
# 4WQeZLW3QOXNmWm7UA018DQEa1yTqEQbuD5OlR1Wu/F289DmXNTdsZM4GTKEaZeh
# IiVaMoLvEJtu5h6CTyfWqPetNyOJqR1sGqod0Xwn5/G/zcTYSxn5K3N8KdlcDrZA
# Iyfq3yaEJYHGnA9eJ/f1RrfbJgeo/RAhICctOONwfpsBXcgiTuTmlD/k0DqogvzJ
# gPq9GOkIyX/dxk7IkPzX/n484s0zHR4IKU58U3G1oPSQmZ5OHAvgHaEASkdN5E20
# HyJv5zN7du+QY08fI+VIci6pagLfXHYaTX3ZJ/MUM9XU+oU5y4qMLzTj1JIG0LVf
# uHK8yoB7h2inyTe7bn6h2G8NxZ02aKZ0xa+n/JnoXKNsaVPG1SoTuItMsXV5pQtI
# ShsBqnXqFjY3bJMlMhIofMcjiuOwRCW+prZ+PoYvE2P+ML7gs3L65GZ9BdKF3fSW
# 3TvmpOujPQ23rzSle9WGxFJ02fNbaF9C7bG44uDzMoZU4P+uvQaB7KE4OMqAvYYf
# Fy1tv1dpVIN/qhx0H/9oNiOJpuZZ39ZibLt9DXbsq5qwyHmdJXaisxwB53wJshUj
# c1i76xqFPUNGb8EZQ3aFKl2w9B47vfBi+nU3sN0tpnLPtew4LHWq4LBD5uiNZVBO
# YosZ6BKhSlk1+Y/0y1IxghsmMIIbIgIBATBYMEExEzARBgoJkiaJk/IsZAEZFgNH
# QkwxEzARBgoJkiaJk/IsZAEZFgNBTUUxFTATBgNVBAMTDEFNRSBDUyBDQSAwMQIT
# NgAAAIdq4V+wb367dAABAAAAhzANBglghkgBZQMEAgEFAKCBxjAZBgkqhkiG9w0B
# CQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAv
# BgkqhkiG9w0BCQQxIgQgWIlMPy4A0nE74nD9DrqGYzdfh+yfx7L0NK0Acv5tozww
# WgYKKwYBBAGCNwIBDDFMMEqgLIAqAE0AaQBjAHIAbwBzAG8AZgB0ACAAQwBvAHIA
# cABvAHIAYQB0AGkAbwBuoRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTANBgkq
# hkiG9w0BAQEFAASCAQBT5JJgDockhEdcJyQXpVy1AOKQGValpthJA7Pcm6sE2Xew
# nEdI4apy00iAMyDXHHL4cWZa3zY9S1pKdLSJ2FD2gatSTt9Kfo844nDHVin5AAj6
# MGslqyu3e/fIyMtc+mTqO9o51F7Z/Z4A19r1w+2TZtos45NwBdGwrl5/Md1Zdi+n
# tEkJ+lTxBGra6Dd0T5pJ0gu4VKBfjlgenCGAf6QOe3D+8JGvBeCgDiluR6fQhPcC
# c3hJOrB8aNBq/IiGW3EIK7oUdrGepMJTNLglDavtqJ3BODJc+wYGYyCXARWdcHft
# yucYf6URK9W8+Fl6l6f0bcbZ3nZe+hAm8Nnzfq8+oYIY1jCCGNIGCisGAQQBgjcD
# AwExghjCMIIYvgYJKoZIhvcNAQcCoIIYrzCCGKsCAQMxDzANBglghkgBZQMEAgEF
# ADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEw
# DQYJYIZIAWUDBAIBBQAEIEQrvsqiyvxN49/FpX5TXEVZpNsIdPN4KBZKQsRwtdmT
# AgZbcv/s9c4YEzIwMTgwODIzMTUwNDQzLjk0NFowBIACAfSggdCkgc0wgcoxCzAJ
# BgNVBAYTAlVTMQswCQYDVQQIEwJXQTEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OjNCRDQtNEI4MC02OUMzMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBz
# ZXJ2aWNloIIULTCCBPEwggPZoAMCAQICEzMAAAC+YA8yBRsgEp0AAAAAAL4wDQYJ
# KoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMTgw
# MTMxMTkwMDQyWhcNMTgwOTA3MTkwMDQyWjCByjELMAkGA1UEBhMCVVMxCzAJBgNV
# BAgTAldBMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMg
# TGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0JENC00QjgwLTY5QzMx
# JTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIHNlcnZpY2UwggEiMA0GCSqG
# SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCQZQlchBCgrPLkGbdTlwOXzIxNGzgXO1Rc
# GMk934na3Af5foKKS+0R8akQfdybcOo/lSJj1ewpmlSoHDmq2+7uMLA3MVV/coO2
# lm6RsQLt7oOlfzV7jOvWymqpzyd7liDtHxu1id/7Sc7JhZcw5n8xCzQvuZNau4sR
# Nkq6XPfyRI5h/+cHAxR8ZyJzMBQ4WYwx9EAgA5JoVP4FPEwS+UXe5BhPdeiR27nb
# 9rBWoiAZj7eO0ElTBgMfS8D2vBYaEGH0/QlilY5Et9CIHSKNjaWUIzQ7aZSKOTwF
# QdSlPklcnGnbMRHNsSjjk0Isc4ui06FKpLmISl0pU1izgceCQFULAgMBAAGjggEb
# MIIBFzAdBgNVHQ4EFgQUDG9/BhZbE7yHjgLO3WZ+2W63InMwHwYDVR0jBBgwFoAU
# 1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2Ny
# bC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljVGltU3RhUENBXzIw
# MTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNUaW1TdGFQQ0FfMjAxMC0w
# Ny0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkq
# hkiG9w0BAQsFAAOCAQEARz1F5awQVEVGdrXaYkvNjrFFy5Ay+976CNkiOZVUHk6H
# zCqOlbT1ffKU8dM5Sb4oSytdD2L3lNIArRtX4zNGl3Q3JcTVIYFQu9Od3OI1Vksh
# +4d15UsLv/vZLW/x7FisHDnMITuf37RHBspAefZIR896cr2FhxvXQGxSXdVsyIq/
# Fuk4WPJk2y08y9k6vWtLYopZOiAqwceaDxDgg8qSmZM6MxAiHaoecW9iOYoS2rhl
# GknXb7TI2D7Xu502UM/r4MknODxV8tY7kty0OQ/Ogj4TaFLV/OvJcIVoGSvwBu3y
# TXY5whjtxNJBhiyOpOeZR8FHZI9wfhNj2ssujG6hdjCCBe0wggPVoAMCAQICECjM
# OiW/ukSsRJqbWGtDOaowDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENl
# cnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTEwMDYyMzIxNTcyNFoXDTM1MDYy
# MzIyMDQwMVowgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# MjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAy
# MDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuQieKOTk7AZOUGiz
# QcV76662jq+BuiJEH2U0aUy+cEAX8hZ74nn9hu0NOfQbqK2SkB7LPXaPWtm1kRAu
# PAWNim0kVOcf7Vatg7RQnBWlF3SIWSD8CMWEdtNo1G8oeM5cuPNQkET/42NfvqGa
# LJYVBNYH/h6EIeBCMRHEKDaUz1CkYp7J1qtxALJbDOaW1AoklvX/xtW3G9fLtyFi
# rxLcoV034xr7GkaYwJvA52MfKgiTAn4eao7ynxiJ5CKForGEV0D/9Q7Yb5zt4kUx
# Ac0X6X+wgUXjqiFAJqFyqqdPPAEFfu6DWLFeBmOZYpF4grcNkwwkarQb2yfsX5UE
# P5NKMPWXGLOn+RmnkzMdAcjbIlJc1yXJRvmi+4dZQ76bYrGNLYZEGkaseGF+MAn6
# ronEQSoiZgOROUWcx4sMqMoNL/tS6gz3YzMjnf6wH61n1qdQA8YEcGO1LLGGWkO3
# +675biluISFBJgaMycPusMKFk6G5hdnmMmxLTD/WXaPltZ13w5zAVbd0AOO4OKuD
# l1DhmkIkHcbAozDRGlrIUjT3c/HHGB8zrXrsy0Fg8yOUIMJIRaxcUcYugMLidxW9
# hYftNp2Wke4AtaNw7J/jjYBog3a6r11wUiIW4mb7urPFwvc+L3emyt7BpsZITMM3
# USPTJ9e4TnCW8KFEdq94z5rhZhMCAwEAAaNRME8wCwYDVR0PBAQDAgGGMA8GA1Ud
# EwEB/wQFMAMBAf8wHQYDVR0OBBYEFNX2VsuP6KJcYmjRPZSQW9fOmhjEMBAGCSsG
# AQQBgjcVAQQDAgEAMA0GCSqGSIb3DQEBCwUAA4ICAQCspZaMv7uupvbXcYdDMVaI
# /RwycVs1t9TwkfKvN+IU8fMCJgU+FhR/FLq4T/uJsrLn1AnMbblbO2RlcGa38rFa
# 3xoC8/VRuGdtefO/VnvkhLkrHptAnCY0+UcYmGnYHNe20b+PYcJnxLXvYEOOEBs2
# SeQgyq2nwbEnZQn4zfVbKtCEM/PvH/L1nAtYkzegdaDect5sdSpmIvWMBjBWn0C5
# MKpAdxWC14vswNOyvYPFdwwerq8ZU6BNeXGfD68wzmf51izMIkF6B/KXQhjOWXkQ
# Vd5vEOS42oNmQBYJaCNbly4mmgK7V4zFuLppYjKAiZ6h/cCSfHsrMxmEKmPFAGhi
# +p9HjZl6RTqn6e3uaUK184GbR1YQe/xwNoQYc+rv+ZdNnjMj3SYLuiq3P0Tcgyf/
# vWFZKxG3yk/bxYsMHDGuMvj4uUL3f9xhmnaxWgThET1mRbcYcb7JJIXW89S6QTRd
# Ei0luY2mE0htS7AHfZmTCWGBdFcmiqtp4+TZx4jMJNjsUiRcHryRFOKW3usK2p7d
# X7Nb29SC7MYgUIclQDr7x+7N/jPlbsOECVUDJTnA6TVdZTGo9r+gCc0px7M2Mi7c
# lfODwVrPi4326rMh+KTtHjEOtkwRq2ALpBIjIhejNmSCkQQS4KtvHstQBWG0QP9Z
# hnHR1TNpfKlzijjXZAzxaTCCBnEwggRZoAMCAQICCmEJgSoAAAAAAAIwDQYJKoZI
# hvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# MjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAy
# MDEwMB4XDTEwMDcwMTIxMzY1NVoXDTI1MDcwMTIxNDY1NVowfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQCpHQ28dxGKOiDs/BOX9fp/aZRrdFQQ1aUKAIKF++18aEssX8XD5WHCdrc+Zitb
# 8BVTJwQxH0EbGpUdzgkTjnxhMFmxMEQP8WCIhFRDDNdNuDgIs0Ldk6zWczBXJoKj
# RQ3Q6vVHgc2/JGAyWGBG8lhHhjKEHnRhZ5FfgVSxz5NMksHEpl3RYRNuKMYa+YaA
# u99h/EbBJx0kZxJyGiGKr0tkiVBisV39dx898Fd1rL2KQk1AUdEPnAY+Z3/1ZsAD
# lkR+79BL/W7lmsqxqPJ6Kgox8NpOBpG2iAg16HgcsOmZzTznL0S6p/TcZL2kAcEg
# CZN4zfy8wMlEXV4WnAEFTyJNAgMBAAGjggHmMIIB4jAQBgkrBgEEAYI3FQEEAwIB
# ADAdBgNVHQ4EFgQU1WM6XIoxkPNDe3xGG8UzaFqFbVUwGQYJKwYBBAGCNxQCBAwe
# CgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0j
# BBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0
# cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2Vy
# QXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRf
# MjAxMC0wNi0yMy5jcnQwgaAGA1UdIAEB/wSBlTCBkjCBjwYJKwYBBAGCNy4DMIGB
# MD0GCCsGAQUFBwIBFjFodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vUEtJL2RvY3Mv
# Q1BTL2RlZmF1bHQuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAFAA
# bwBsAGkAYwB5AF8AUwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUA
# A4ICAQAH5ohRDeLG4Jg/gXEDPZ2joSFvs+umzPUxvs8F4qn++ldtGTCzwsVmyWrf
# 9efweL3HqJ4l4/m87WtUVwgrUYJEEvu5U4zM9GASinbMQEBBm9xcF/9c+V4XNZgk
# Vkt070IQyK+/f8Z/8jd9Wj8c8pl5SpFSAK84Dxf1L3mBZdmptWvkx872ynoAb0sw
# RCQiPM/tA6WWj1kpvLb9BOFwnzJKJ/1Vry/+tuWOM7tiX5rbV0Dp8c6ZZpCM/2pi
# f93FSguRJuI57BlKcWOdeyFtw5yjojz6f32WapB4pm3S4Zz5Hfw42JT0xqUKloak
# vZ4argRCg7i1gJsiOCC1JeVk7Pf0v35jWSUPei45V3aicaoGig+JFrphpxHLmtgO
# R5qAxdDNp9DvfYPw4TtxCd9ddJgiCGHasFAeb73x4QDf5zEHpJM692VHeOj4qEir
# 995yfmFrb3epgcunCaw5u+zGy9iCtHLNHfS4hQEegPsbiSpUObJb2sgNVZl6h3M7
# COaYLeqN4DMuEin1wC9UJyH3yKxO2ii4sanblrKnQqLJzxlBTeCG+SqaoxFmMNO7
# dDJL32N79ZmKLxvHIa9Zta7cRDyXUHHXodLFVeNp3lfB0d4wwP3M5k37Db9dT+md
# Hhk4L7zPWAUu7w2gUDXa7wknHNWzfjUeCLraNtvTX4/edIhJEqGCAs4wggI3AgEB
# MIH4oYHQpIHNMIHKMQswCQYDVQQGEwJVUzELMAkGA1UECBMCV0ExEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UE
# CxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQL
# Ex1UaGFsZXMgVFNTIEVTTjozQkQ0LTRCODAtNjlDMzElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgc2VydmljZaIjCgEBMAcGBSsOAwIaAxUANBEpXI/CDnEx
# S5eM6Zcdt0pGT/6ggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDANBgkqhkiG9w0BAQUFAAIFAN8osvkwIhgPMjAxODA4MjMxMjEzNDVaGA8yMDE4
# MDgyNDEyMTM0NVowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA3yiy+QIBADAKAgEA
# AgIcRgIB/zAHAgEAAgIRHjAKAgUA3yoEeQIBADA2BgorBgEEAYRZCgQCMSgwJjAM
# BgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEB
# BQUAA4GBAFo2voeuJG3bWH5o+YpA2K+y80tPk0WnDw6Z6m/IiWYc55a3h5Tdz86o
# ZTQzpWb3BtyblelEMgo00I/rnlV3OrTjUxdg6gr+YC1wPOpwOkBMGe2DffGK0xlK
# amBS0pUe2a+0m8gdHjWv11+4HL/cg/Pwkfrub9aVt/dySObbW3jwMYIDDTCCAwkC
# AQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAC+YA8yBRsg
# Ep0AAAAAAL4wDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG
# 9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgXKM12Zft7decN8B6MdB0rWobYBv+rkw9
# app3NH+lYicwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAM+wQUb5IeCE+Y
# KfoH5E/3nRgT78h6EpbJuMJJ4FzJpjCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFBDQSAyMDEwAhMzAAAAvmAPMgUbIBKdAAAAAAC+MCIEIDRWkrm6RZfGPX2C
# jtibokqlyu8bQ96ELi5g2cwFI+x3MA0GCSqGSIb3DQEBCwUABIIBACLXNPz9VT3j
# 6AFXJe2rvVRJutZeCTk2Wyr8BB0kXGpfFf7NPdPCBH3+53E9FgHBaruNSoFM4rM6
# oD8UxxhP3SegWYaaQ095esNkQp38634IUF1/8XQuxjT1vereN4716f3e4uH/J+/s
# KLxbsX7kiyzyo4Vr0IpJiuoRIxDMZ7aZaqtHoJf9yDXFs0fqTwrKVdTFnZhrHZJ/
# hL6On55nsGg6HXjbTDZ8BwFnaQfqzcWbPSWbq6IyPq5QoAZbFMCQrhnJBo4bWQzU
# M1TUKKgbJ6VWIr2L0Gdvs6pebmkpskonzXX6dpea1ZLp5s58O9Ly9D7GA/9w4k4S
# dTIDajDMc54=
# SIG # End signature block
