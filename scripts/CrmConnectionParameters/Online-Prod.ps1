# a connection to a Dynamics 365 Online deployment
# update the values as appropriate

# uncomment this when connecting to Dynamics 365 v9.x to ensure TLS 1.2 is used
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

@{
    OrganizationName = "orgd55873f8" # see Settings > Customizations > Developer Resources > "Unique Name"
    ServerUrl = "https://org6dbf7cbe.crm3.dynamics.com" # the online organization URL
    Credential = (Get-Credential) # prompt for credentials
}