function Get-RWDomainController {
    <#
    .SYNOPSIS
        Returns Read-Write Domain Controller computer accounts from Active Directory.

    .DESCRIPTION
        Queries Active Directory via ADSI for computer accounts whose primaryGroupID
        is 516 (the "Domain Controllers" security group), which identifies Read-Write
        Domain Controllers. Read-Only Domain Controllers (RODCs) have primaryGroupID
        521 and are excluded.

        This function uses ADSI / System.DirectoryServices and does not require
        the ActiveDirectory PowerShell module.

    .PARAMETER Server
        Domain controller to query. Defaults to the current domain.

    .PARAMETER Credential
        Credentials for the LDAP connection. Defaults to the current user context.

    .EXAMPLE
        Get-RWDomainController

        Returns all Read-Write Domain Controller accounts in the current domain.

    .EXAMPLE
        Get-RWDomainController -Server dc01.contoso.com -Credential (Get-Credential)

        Queries a specific domain controller with alternate credentials.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [string]$Server,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )

    $domainEntry = Get-DomainDirectoryEntry -Server $Server -Credential $Credential

    try {
        $searcher = [System.DirectoryServices.DirectorySearcher]::new($domainEntry)
        # primaryGroupID 516 = "Domain Controllers" group → Read-Write DCs only
        $searcher.Filter  = '(&(objectClass=computer)(primaryGroupID=516))'
        $searcher.PropertiesToLoad.AddRange([string[]]@(
            'name', 'sAMAccountName', 'distinguishedName', 'dNSHostName', 'adminCount'
        ))
        $searcher.PageSize = 1000

        try {
            $searchResults = $searcher.FindAll()

            foreach ($result in $searchResults) {
                $rawAdminCount = $result.Properties['adminCount']
                $adminCount    = if ($rawAdminCount.Count -gt 0) { [int]$rawAdminCount[0] } else { 0 }

                [PSCustomObject]@{
                    Name              = $result.Properties['name'][0]
                    SamAccountName    = $result.Properties['sAMAccountName'][0]
                    DistinguishedName = $result.Properties['distinguishedName'][0]
                    DnsHostName       = if ($result.Properties['dNSHostName'].Count -gt 0) { $result.Properties['dNSHostName'][0] } else { $null }
                    AdminCount        = $adminCount
                    IsProtected       = $adminCount -eq 1
                }
            }
        } finally {
            $searchResults.Dispose()
            $searcher.Dispose()
        }
    } finally {
        $domainEntry.Dispose()
    }
}
