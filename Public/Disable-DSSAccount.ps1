function Disable-DSSAccount {
    <#
    .SYNOPSIS
        Disables an Active Directory account.
    .DESCRIPTION
        Disables a computer, user or service account in Active Directory.
    .EXAMPLE
        Disable-DSSAccount -SAMAccountName 'Guest'

        Disables the "Guest" account.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/disable-adaccount
    #>

    [CmdletBinding(DefaultParameterSetName = 'SAM', SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        # The SAMAccountName of the account.
        [Parameter(Mandatory = $true, ParameterSetName = 'SAM')]
        [ValidateNotNullOrEmpty()]
        [Alias('SAM')]
        [String]
        $SAMAccountName,

        # The DistinguishedName of the account.
        [Parameter(Mandatory = $true, ParameterSetName = 'DistinguishedName')]
        [ValidateNotNullOrEmpty()]
        [Alias('DN')]
        [String]
        $DistinguishedName,

        # The ObjectSID of the account.
        [Parameter(Mandatory = $true, ParameterSetName = 'SID')]
        [ValidateNotNullOrEmpty()]
        [Alias('SID')]
        [String]
        $ObjectSID,

        # The ObjectGUID of the account.
        [Parameter(Mandatory = $true, ParameterSetName = 'GUID')]
        [ValidateNotNullOrEmpty()]
        [Alias('GUID')]
        [String]
        $ObjectGUID,

        # The context to search - Domain or Forest.
        [Parameter(Mandatory = $false)]
        [ValidateSet('Domain', 'Forest')]
        [String]
        $Context = 'Domain',

        # The server to connect to.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Server,

        # The credential to use for access.
        [Parameter(Mandatory = $false)]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    try {
        $Directory_Search_Parameters = @{
            'Context'      = $Context
            'OutputFormat' = 'DirectoryEntry'
        }
        if ($PSBoundParameters.ContainsKey('Server')) {
            $Directory_Search_Parameters['Server'] = $Server
        }
        if ($PSBoundParameters.ContainsKey('Credential')) {
            $Directory_Search_Parameters['Credential'] = $Credential
        }

        if ($PSBoundParameters.ContainsKey('SAMAccountName')) {
            $Directory_Search_LDAPFilter = '(samaccountname={0})' -f $SAMAccountName
            $Directory_Search_Type = 'SAMAccountName'
            $Directory_Search_Value = $SAMAccountName
        } elseif ($PSBoundParameters.ContainsKey('DistinguishedName')) {
            $Directory_Search_LDAPFilter = '(distinguishedname={0})' -f $DistinguishedName
            $Directory_Search_Type = 'DistinguishedName'
            $Directory_Search_Value = $DistinguishedName
        } elseif ($PSBoundParameters.ContainsKey('ObjectSID')) {
            $Directory_Search_LDAPFilter = '(objectsid={0})' -f $ObjectSID
            $Directory_Search_Type = 'ObjectSID'
            $Directory_Search_Value = $ObjectSID
        } elseif ($PSBoundParameters.ContainsKey('ObjectGUID')) {
            $Directory_Search_LDAPFilter = '(objectguid={0})' -f (Convert-GuidToHex -Guid $ObjectGUID)
            $Directory_Search_Type = 'ObjectGUID'
            $Directory_Search_Value = $ObjectGUID
        }
        Write-Verbose ('{0}|LDAPFilter: {1}' -f $Function_Name, $Directory_Search_LDAPFilter)
        $Directory_Search_Parameters['LDAPFilter'] = $Directory_Search_LDAPFilter

        Write-Verbose ('{0}|Calling Find-DSSRawObject to get DirectoryEntry' -f $Function_Name)
        $Account_Directory_Entry = Find-DSSRawObject @Directory_Search_Parameters
        if ($Account_Directory_Entry) {
            $UAC_AccountDisabled = '0x02'
            if ($PSCmdlet.ShouldProcess($Account_Directory_Entry.distinguishedname, 'Set')) {
                if (($Account_Directory_Entry.useraccountcontrol.Value -band $UAC_AccountDisabled) -ne $UAC_AccountDisabled) {
                    Write-Verbose ('{0}|Account is Enabled, disabling' -f $Function_Name)
                    $Account_Directory_Entry.useraccountcontrol.Value = $Account_Directory_Entry.useraccountcontrol.Value -bxor $UAC_AccountDisabled
                    try {
                        $Account_Directory_Entry.SetInfo()
                    } catch {
                        $Terminating_ErrorRecord_Parameters = @{
                            'Exception'      = 'System.UnauthorizedAccessException'
                            'ID'             = 'DSS-{0}' -f $Function_Name
                            'Category'       = 'AuthenticationError'
                            'TargetObject'   = $Account_Directory_Entry
                            'Message'        = 'Insufficient access rights to perform the operation'
                            'InnerException' = $_.Exception
                        }
                        $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                        $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                    }
                } else {
                    Write-Verbose ('{0}|Account is already Disabled, doing nothing' -f $Function_Name)
                }
            }
        } else {
            $Terminating_ErrorRecord_Parameters = @{
                'Exception'    = 'System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException'
                'ID'           = 'DSS-{0}' -f $Function_Name
                'Category'     = 'ObjectNotFound'
                'TargetObject' = $Account_Directory_Entry
                'Message'      = 'Cannot find account with {0} of "{1}"' -f $Directory_Search_Type, $Directory_Search_Value
            }
            $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        }
    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}
