function Get-DomainDirectoryEntry {
    <#
    .SYNOPSIS
        Returns a DirectoryEntry for the specified distinguished name using ADSI.
    .PARAMETER DistinguishedName
        The distinguished name of the object to bind to. When omitted the domain
        root (defaultNamingContext) is used.
    .PARAMETER Server
        Optional domain controller hostname or IP.
    .PARAMETER Credential
        Optional credentials for the LDAP connection.
    #>
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.DirectoryEntry])]
    param(
        [Parameter()]
        [string]$DistinguishedName,

        [Parameter()]
        [string]$Server,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )

    if (-not $DistinguishedName) {
        $rootDSE = Get-DomainRootDSE -Server $Server -Credential $Credential
        try {
            $DistinguishedName = $rootDSE.Properties['defaultNamingContext'][0]
        } finally {
            $rootDSE.Dispose()
        }
    }

    $path = if ($Server) { "LDAP://$Server/$DistinguishedName" } else { "LDAP://$DistinguishedName" }

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
