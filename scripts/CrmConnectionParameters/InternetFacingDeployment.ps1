# a connection to an internet facing deployment
# update the values as appropriate
@{
    OrganizationName = "fabrikam" # the organization name
    ServerUrl = "https://fabrikam.crm.contoso.com" # the Internet-Facing Deployment organization URL
    Credential = (Get-Credential) # prompt for credentials
} 
