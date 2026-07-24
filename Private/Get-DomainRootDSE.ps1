function Get-DomainRootDSE {
    <#
    .SYNOPSIS
        Returns the RootDSE DirectoryEntry for a domain using ADSI.
    .PARAMETER Server
        Optional domain controller hostname or IP. Defaults to the current domain.
    .PARAMETER Credential
        Optional credentials for the LDAP connection.
    #>
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.DirectoryEntry])]
    param(
        [Parameter()]
        [string]$Server,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )

    $path = if ($Server) { "LDAP://$Server/RootDSE" } else { 'LDAP://RootDSE' }

    if ($Credential) {
        [System.DirectoryServices.DirectoryEntry]::new(
            $path,
            $Credential.UserName,
            $Credential.GetNetworkCredential().Password
        )
    } else {
        [System.DirectoryServices.DirectoryEntry]::new($path)
    }
}
