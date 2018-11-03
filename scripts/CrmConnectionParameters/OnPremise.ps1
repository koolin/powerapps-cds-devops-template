# a connection to an on-premise deployment using active directory authentication
# update the values as appropriate
@{
    OrganizationName = "fabrikam" # the organization name
    ServerUrl = "http://dyn365.contoso.com" # the on-premise server URL
    Credential = [PSCredential]::new("contoso\administrator", ("pass@word1" | ConvertTo-SecureString -AsPlainText -Force)) # hard-coded credentials
}