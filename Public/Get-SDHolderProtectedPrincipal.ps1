function Get-SDHolderProtectedPrincipal {
    <#
    .SYNOPSIS
        Retrieves Active Directory principals protected by AdminSDHolder.

    .DESCRIPTION
        Returns all user and computer accounts that carry adminCount=1, indicating
        they are (or were) covered by the SDProp process. Read-Write Domain
        Controller computer accounts are included by default because they belong to
        the "Domain Controllers" protected group (primaryGroupID 516) and must be
        accounted for in AdminSDHolder coverage.

        This function uses ADSI / System.DirectoryServices and does not require
        the ActiveDirectory PowerShell module.

    .PARAMETER Server
        Domain controller to query. Defaults to the current domain.

    .PARAMETER Credential
        Credentials for the LDAP connection. Defaults to the current user context.

    .PARAMETER ExcludeRWDomainControllers
        When specified, Read-Write Domain Controller computer accounts are omitted
        from the results.

    .EXAMPLE
        Get-SDHolderProtectedPrincipal

        Returns all protected principals (users and computers, including RW DCs)
        in the current domain.

    .EXAMPLE
        Get-SDHolderProtectedPrincipal -Server dc01.contoso.com -Credential (Get-Credential)

        Queries the specified domain controller with alternate credentials.

    .EXAMPLE
        Get-SDHolderProtectedPrincipal -ExcludeRWDomainControllers

        Returns protected principals, omitting RW Domain Controller computer accounts.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [string]$Server,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [switch]$ExcludeRWDomainControllers
    )

    $domainEntry = Get-DomainDirectoryEntry -Server $Server -Credential $Credential

    try {
        $searcher = [System.DirectoryServices.DirectorySearcher]::new($domainEntry)
        # Retrieve users and computer accounts carrying adminCount=1; exclude group objects
        $searcher.Filter  = '(&(adminCount=1)(|(objectClass=user)(objectClass=computer)))'
        $searcher.PropertiesToLoad.AddRange([string[]]@(
            'name', 'sAMAccountName', 'distinguishedName',
            'objectClass', 'primaryGroupID'
        ))
        $searcher.PageSize = 1000

        try {
            $searchResults = $searcher.FindAll()

            foreach ($result in $searchResults) {
                $classes       = $result.Properties['objectClass']
                $primaryGID    = [int]$result.Properties['primaryGroupID'][0]

                $isComputer    = $classes -contains 'computer'
                # RW DCs have primaryGroupID 516 ("Domain Controllers").
                # RODCs have primaryGroupID 521 ("Read-only Domain Controllers").
                $isRWDC        = $isComputer -and ($primaryGID -eq 516)

                if ($ExcludeRWDomainControllers -and $isRWDC) {
                    continue
                }

                [PSCustomObject]@{
                    Name                 = $result.Properties['name'][0]
                    SamAccountName       = $result.Properties['sAMAccountName'][0]
                    DistinguishedName    = $result.Properties['distinguishedName'][0]
                    ObjectType           = if ($isComputer) { 'Computer' } else { 'User' }
                    IsRWDomainController = $isRWDC
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
