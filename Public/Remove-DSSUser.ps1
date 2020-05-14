function Remove-DSSUser {
    <#
    .SYNOPSIS
        Removes a specific user object from Active Directory.
    .DESCRIPTION
        Queries Active Directory for a specific user object and then deletes it, based on one of the following specified parameters:
            - DistinguishedName
            - ObjectSID (SID)
            - ObjectGUID (GUID)
            - SAMAccountName
    .EXAMPLE
        Remove-DSSUser -ObjectGUID 'b675195d-e637-447e-ad26-baded4df1ba0'

        Deletes the user with the above GUID.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/remove-aduser
    #>

    [CmdletBinding(DefaultParameterSetName = 'SAM', SupportsShouldProcess = $true)]
    param(
        # The SAMAccountName of the user.
        [Parameter(Mandatory = $true, ParameterSetName = 'SAM')]
        [ValidateNotNullOrEmpty()]
        [Alias('SAM')]
        [String]
        $SAMAccountName,

        # The DistinguishedName of the user.
        [Parameter(Mandatory = $true, ParameterSetName = 'DistinguishedName')]
        [ValidateNotNullOrEmpty()]
        [Alias('DN')]
        [String]
        $DistinguishedName,

        # The ObjectSID of the user.
        [Parameter(Mandatory = $true, ParameterSetName = 'SID')]
        [ValidateNotNullOrEmpty()]
        [Alias('SID')]
        [String]
        $ObjectSID,

        # The ObjectGUID of the user.
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
        if ($SAMAccountName -match '\*') {
            $Terminating_ErrorRecord_Parameters = @{
                'Exception'    = 'System.ArgumentException'
                'ID'           = 'DSS-{0}' -f $Function_Name
                'Category'     = 'SyntaxError'
                'TargetObject' = $SAMAccountName
                'Message'      = 'SAMAccountName cannot include wildcards'
            }
            $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        }

        $Common_Search_Parameters = @{
            'Context' = $Context
        }
        if ($PSBoundParameters.ContainsKey('Server')) {
            $Common_Search_Parameters['Server'] = $Server
        }
        if ($PSBoundParameters.ContainsKey('Credential')) {
            $Common_Search_Parameters['Credential'] = $Credential
        }

        $Confirm_Parameters = @{}
        # This will add the -Confirm parameter if ConfirmPreference is set high enough.
        # The Set-DSSRawObject doesn't have a default ConfirmImpact set, so this passes the ConfirmImpact from this function if required.
        if (-not $PSBoundParameters.ContainsKey('Confirm')) {
            $ConfirmImpact = 'High'
            if ([System.Management.Automation.ConfirmImpact]::$ConfirmImpact.Value__ -ge [System.Management.Automation.ConfirmImpact]::$ConfirmPreference.Value__) {
                Write-Verbose ('{0}|Adding Confirm parameter' -f $Function_Name)
                $Confirm_Parameters['Confirm'] = $True
            }
        }
        if ($PSBoundParameters.ContainsKey('WhatIf')) {
            $Confirm_Parameters['WhatIf'] = $WhatIf
        }

        $Default_LDAPFilter = '(objectclass=user)'
        if ($PSBoundParameters.ContainsKey('SAMAccountName')) {
            $LDAPFilter = '(&{0}(samaccountname={1}))' -f $Default_LDAPFilter, $SAMAccountName
            $Directory_Search_Type = 'SAMAccountName'
            $Directory_Search_Value = $SAMAccountName
        } elseif ($PSBoundParameters.ContainsKey('DistinguishedName')) {
            $LDAPFilter = '(&{0}(distinguishedname={1}))' -f $Default_LDAPFilter, $DistinguishedName
            $Directory_Search_Type = 'DistinguishedName'
            $Directory_Search_Value = $DistinguishedName
        } elseif ($PSBoundParameters.ContainsKey('ObjectSID')) {
            $LDAPFilter = '(&{0}(objectsid={1}))' -f $Default_LDAPFilter, $ObjectSID
            $Directory_Search_Type = 'ObjectSID'
            $Directory_Search_Value = $ObjectSID
        } else {
            $LDAPFilter = '(&{0}(objectguid={1}))' -f $Default_LDAPFilter, $ObjectGUID
            $Directory_Search_Type = 'ObjectGUID'
            $Directory_Search_Value = $ObjectGUID
        }
        $Directory_Search_Parameters = @{
            'LDAPFilter'   = $LDAPFilter
            'OutputFormat' = 'DirectoryEntry'
        }

        $Object_Directory_Entry = Find-DSSRawObject @Common_Search_Parameters @Directory_Search_Parameters
        if ($Object_Directory_Entry) {
            $Set_Parameters = @{
                'Action' = 'RemoveObject'
                'Object' = $Object_Directory_Entry
            }
            Write-Verbose ('{0}|Calling Set-DSSRawObject' -f $Function_Name)
            Set-DSSRawObject @$Common_Search_Parameters @Set_Parameters @Confirm_Parameters
        } else {
            $Terminating_ErrorRecord_Parameters = @{
                'Exception'    = 'System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException'
                'ID'           = 'DSS-{0}' -f $Function_Name
                'Category'     = 'ObjectNotFound'
                'TargetObject' = $Object_Directory_Entry
                'Message'      = 'Cannot find User with {0} of "{1}"' -f $Directory_Search_Type, $Directory_Search_Value
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
