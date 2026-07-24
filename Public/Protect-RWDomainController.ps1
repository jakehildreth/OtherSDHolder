function Protect-RWDomainController {
    <#
    .SYNOPSIS
        Ensures that Read-Write Domain Controller computer accounts are protected
        by the AdminSDHolder mechanism.

    .DESCRIPTION
        Addresses the gap where Read-Write Domain Controller computer accounts are
        not covered by SDProp protection. This function sets adminCount=1 on any
        RW DC computer account that is currently missing that attribute and applies
        the security descriptor from the AdminSDHolder object to the account.

        Membership in the "Domain Controllers" group (primaryGroupID 516) already
        qualifies these accounts for AdminSDHolder coverage; however, SDProp may not
        have run yet, or adminCount may have been cleared manually. This function
        explicitly enforces the protected state without waiting for the next SDProp
        cycle.

        This function uses ADSI / System.DirectoryServices and does not require
        the ActiveDirectory PowerShell module.

    .PARAMETER Server
        Domain controller to target. Defaults to the current domain.

    .PARAMETER Credential
        Credentials for the LDAP connection. Defaults to the current user context.

    .PARAMETER WhatIf
        Shows what changes would be made without applying them.

    .PARAMETER Confirm
        Prompts for confirmation before applying each change.

    .EXAMPLE
        Protect-RWDomainController

        Sets adminCount=1 on any unprotected RW DC accounts in the current domain
        and copies the AdminSDHolder security descriptor to each.

    .EXAMPLE
        Protect-RWDomainController -Server dc01.contoso.com -Credential (Get-Credential) -WhatIf

        Previews which RW DC accounts would be updated.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [string]$Server,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )

    # Retrieve the AdminSDHolder security descriptor to apply to unprotected DCs
    $rootDSE = Get-DomainRootDSE -Server $Server -Credential $Credential
    try {
        $domainDN        = $rootDSE.Properties['defaultNamingContext'][0]
        $configDN        = $rootDSE.Properties['configurationNamingContext'][0]
    } finally {
        $rootDSE.Dispose()
    }

    $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$domainDN"
    $adminSDEntry    = Get-DomainDirectoryEntry -DistinguishedName $adminSDHolderDN -Server $Server -Credential $Credential

    try {
        $adminSDEntry.RefreshCache([string[]]@('nTSecurityDescriptor'))
        $adminSD = $adminSDEntry.Properties['nTSecurityDescriptor'][0]
    } finally {
        $adminSDEntry.Dispose()
    }

    # Find RW DC accounts that are not yet protected (adminCount != 1)
    $unprotectedDCs = Get-RWDomainController -Server $Server -Credential $Credential |
        Where-Object { -not $_.IsProtected }

    foreach ($dc in $unprotectedDCs) {
        if ($PSCmdlet.ShouldProcess($dc.DistinguishedName, 'Set adminCount=1 and apply AdminSDHolder security descriptor')) {
            $dcEntry = Get-DomainDirectoryEntry -DistinguishedName $dc.DistinguishedName -Server $Server -Credential $Credential

            try {
                # Set adminCount = 1
                $dcEntry.Properties['adminCount'].Value = 1

                # Apply the AdminSDHolder security descriptor
                $dcEntry.Properties['nTSecurityDescriptor'].Value = $adminSD

                $dcEntry.CommitChanges()

                Write-Verbose "Protected RW Domain Controller: $($dc.Name)"

                [PSCustomObject]@{
                    Name              = $dc.Name
                    DistinguishedName = $dc.DistinguishedName
                    Action            = 'Protected'
                    Success           = $true
                }
            } catch {
                Write-Error "Failed to protect RW Domain Controller '$($dc.Name)': $_"

                [PSCustomObject]@{
                    Name              = $dc.Name
                    DistinguishedName = $dc.DistinguishedName
                    Action            = 'Failed'
                    Success           = $false
                }
            } finally {
                $dcEntry.Dispose()
            }
        }
    }
}
