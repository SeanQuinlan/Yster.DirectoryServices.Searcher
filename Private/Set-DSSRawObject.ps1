function Set-DSSRawObject {
    <#
    .SYNOPSIS
        Make a modification to a specific object from Active Directory.
    .DESCRIPTION
        Queries Active Directory for a specific object and then performs a modification to it.

        This is not meant to be used as an interactive function; it is used as a worker function by many of the other higher-level functions.
    .EXAMPLE
        Set-DSSRawObject -SetType Remove -ObjectSID 'S-1-5-21-3515480276-2049723633-1306762111-1103'

        Removes (deletes) the object with the above SID.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/remove-adobject
        https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.directoryentry
        https://docs.microsoft.com/en-us/windows/win32/api/iads/nf-iads-iadsgroup-remove
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.cmdlet.shouldprocess
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        # The type of modification to make.
        [Parameter(Mandatory = $true)]
        [ValidateSet('Enable', 'Disable', 'Remove', 'RemoveGroupMember', 'Unlock')]
        [Alias('Type')]
        [String]
        $SetType,

        # The SAMAccountName of the object.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('SAM')]
        [String]
        $SAMAccountName,

        # The DistinguishedName of the object.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('DN')]
        [String]
        $DistinguishedName,

        # The ObjectSID of the object.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('SID')]
        [String]
        $ObjectSID,

        # The ObjectGUID of the object.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('GUID')]
        [String]
        $ObjectGUID,

        # Delete all child objects recursively.
        [Parameter(Mandatory = $false)]
        [Switch]
        $Recursive,

        # A member or list of members to remove from the group.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('Member')]
        [String[]]
        $Members,

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
        $Common_Search_Parameters = @{
            'Context' = $Context
        }
        if ($PSBoundParameters.ContainsKey('Server')) {
            $Common_Search_Parameters['Server'] = $Server
        }
        if ($PSBoundParameters.ContainsKey('Credential')) {
            $Common_Search_Parameters['Credential'] = $Credential
        }

        if ($PSBoundParameters.ContainsKey('SAMAccountName')) {
            $Specific_Group_LDAPFilter = '(samaccountname={0})' -f $SAMAccountName
            $Directory_Search_Type = 'SAMAccountName'
            $Directory_Search_Value = $SAMAccountName
        } elseif ($PSBoundParameters.ContainsKey('DistinguishedName')) {
            $Specific_Group_LDAPFilter = '(distinguishedname={0})' -f $DistinguishedName
            $Directory_Search_Type = 'DistinguishedName'
            $Directory_Search_Value = $DistinguishedName
        } elseif ($PSBoundParameters.ContainsKey('ObjectSID')) {
            $Specific_Group_LDAPFilter = '(objectsid={0})' -f $ObjectSID
            $Directory_Search_Type = 'ObjectSID'
            $Directory_Search_Value = $ObjectSID
        } elseif ($PSBoundParameters.ContainsKey('ObjectGUID')) {
            $Specific_Group_LDAPFilter = '(objectguid={0})' -f (Convert-GuidToHex -Guid $ObjectGUID)
            $Directory_Search_Type = 'ObjectGUID'
            $Directory_Search_Value = $ObjectGUID
        }
        $Directory_Search_LDAPFilter = '(&{0}{1})' -f $Default_Group_LDAPFilter, $Specific_Group_LDAPFilter
        Write-Verbose ('{0}|LDAPFilter: {1}' -f $Function_Name, $Directory_Search_LDAPFilter)
        $Directory_Search_Parameters = @{
            'LDAPFilter'   = $Directory_Search_LDAPFilter
            'OutputFormat' = 'DirectoryEntry'
        }

        $Confirm_Header = New-Object -TypeName 'System.Text.StringBuilder'
        [void]$Confirm_Header.AppendLine('Confirm')
        [void]$Confirm_Header.AppendLine('Are you sure you want to perform this action?')

        Write-Verbose ('{0}|Calling Find-DSSRawObject to get DirectoryEntry' -f $Function_Name)
        $global:Object_Directory_Entry = Find-DSSRawObject @Common_Search_Parameters @Directory_Search_Parameters
        if ($Object_Directory_Entry) {
            try {
                switch ($SetType) {
                    'Enable' {
                        $Whatif_Statement = 'Performing the operation "Enable" on target "{0}".' -f $($Object_Directory_Entry.'distinguishedname')
                        $Confirm_Statement = $Whatif_Statement
                        if ($PSCmdlet.ShouldProcess($Whatif_Statement, $Confirm_Statement, $Confirm_Header.ToString())) {
                            Write-Verbose ('{0}|Found object, attempting enable' -f $Function_Name)
                            $UAC_AccountDisabled = '0x02'
                            if (($Object_Directory_Entry.useraccountcontrol.Value -band $UAC_AccountDisabled) -eq $UAC_AccountDisabled) {
                                Write-Verbose ('{0}|Account is Disabled, enabling' -f $Function_Name)
                                $Object_Directory_Entry.useraccountcontrol.Value = $Object_Directory_Entry.useraccountcontrol.Value -bxor $UAC_AccountDisabled
                                $Object_Directory_Entry.SetInfo()
                                Write-Verbose ('{0}|Enable successful' -f $Function_Name)
                            } else {
                                Write-Verbose ('{0}|Account is already Enabled, doing nothing' -f $Function_Name)
                            }
                        }
                    }

                    'Disable' {
                        $Whatif_Statement = 'Performing the operation "Disable" on target "{0}".' -f $($Object_Directory_Entry.'distinguishedname')
                        $Confirm_Statement = $Whatif_Statement
                        if ($PSCmdlet.ShouldProcess($Whatif_Statement, $Confirm_Statement, $Confirm_Header.ToString())) {
                            Write-Verbose ('{0}|Found object, attempting disable' -f $Function_Name)
                            $UAC_AccountDisabled = '0x02'
                            if (($Object_Directory_Entry.useraccountcontrol.Value -band $UAC_AccountDisabled) -ne $UAC_AccountDisabled) {
                                Write-Verbose ('{0}|Account is Enabled, disabling' -f $Function_Name)
                                $Object_Directory_Entry.useraccountcontrol.Value = $Object_Directory_Entry.useraccountcontrol.Value -bxor $UAC_AccountDisabled
                                $Object_Directory_Entry.SetInfo()
                                Write-Verbose ('{0}|Disable successful' -f $Function_Name)
                            } else {
                                Write-Verbose ('{0}|Account is already Disabled, doing nothing' -f $Function_Name)
                            }
                        }
                    }

                    'Remove' {
                        $Whatif_Statement = 'Performing the operation "Remove" on target "{0}".' -f $($Object_Directory_Entry.'distinguishedname')
                        $Confirm_Statement = $Whatif_Statement
                        if ($PSCmdlet.ShouldProcess($Whatif_Statement, $Confirm_Statement, $Confirm_Header.ToString())) {
                            Write-Verbose ('{0}|Found object, checking for ProtectFromAccidentalDeletion' -f $Function_Name)
                            $Check_Object = Get-DSSObject -DistinguishedName $Object_Directory_Entry.distinguishedname -Properties 'protectedfromaccidentaldeletion'
                            if ($Check_Object.'protectedfromaccidentaldeletion') {
                                $Terminating_ErrorRecord_Parameters = @{
                                    'Exception'    = 'System.UnauthorizedAccessException'
                                    'ID'           = 'DSS-{0}' -f $Function_Name
                                    'Category'     = 'SecurityError'
                                    'TargetObject' = $Object_Directory_Entry
                                    'Message'      = 'Object is Protected From Accidental Deletion. Remove protection before trying to delete this object.'
                                }
                                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                            }
                            Write-Verbose ('{0}|Attempting delete' -f $Function_Name)
                            if ($Object_Directory_Entry.objectclass -contains 'Group') {
                                Write-Verbose ('{0}|Object is a group, getting parent OU first' -f $Function_Name)
                                $Group_Directory_Entry_Parent_OU = Get-DSSDirectoryEntry @Common_Search_Parameters -Path $Object_Directory_Entry.Parent
                                $Group_Directory_Entry_Parent_OU.Delete('Group', ('CN={0}' -f $Object_Directory_Entry.cn.Value))
                            } elseif ($Object_Directory_Entry.objectclass -contains 'OrganizationalUnit') {
                                Write-Verbose ('{0}|Object is an OU, checking for child objects' -f $Function_Name)
                                if (([array]$Object_Directory_Entry.Children) -and (-not $Recursive)) {
                                    Write-Verbose ('{0}|Found child objects and Recursive switch not present, unable to delete' -f $Function_Name)
                                    $Terminating_ErrorRecord_Parameters = @{
                                        'Exception'    = 'System.DirectoryServices.DirectoryServicesCOMException'
                                        'ID'           = 'DSS-{0}' -f $Function_Name
                                        'Category'     = 'InvalidOperation'
                                        'TargetObject' = $Object_Directory_Entry
                                        'Message'      = 'Failed to remove due to child objects existing.'
                                    }
                                    $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                                    $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                                } else {
                                    Write-Verbose ('{0}|No child objects found, or Recursive switch passed, deleting' -f $Function_Name)
                                    $Object_Directory_Entry.DeleteTree()
                                }
                            } else {
                                $Object_Directory_Entry.DeleteTree()
                            }
                            Write-Verbose ('{0}|Delete successful' -f $Function_Name)
                        }
                    }

                    'RemoveGroupMember' {
                        Write-Verbose ('{0}|Getting group members first' -f $Function_Name)
                        $global:Group_Members_To_Remove = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'
                        $Group_Member_Properties = @(
                            'SAMAccountName'
                            'DistinguishedName'
                            'ObjectSID'
                            'ObjectGUID'
                        )
                        foreach ($Group_Member in $Members) {
                            $Group_Member_To_Remove = $null
                            foreach ($Group_Member_Property in $Group_Member_Properties) {
                                if ($Group_Member_Property -eq 'ObjectGUID') {
                                    # Only proceed if the $Group_Member string is a valid GUID.
                                    if ([System.Guid]::TryParse($Group_Member, [ref][System.Guid]::Empty)) {
                                        $Group_Member = (Convert-GuidToHex -Guid $Group_Member)
                                    } else {
                                        break
                                    }
                                }
                                $Member_Search_Parameters = @{
                                    'OutputFormat' = 'DirectoryEntry'
                                    'LDAPFilter'   = ('({0}={1})' -f $Group_Member_Property, $Group_Member)
                                }
                                $Group_Member_Result = Find-DSSRawObject @Common_Search_Parameters @Member_Search_Parameters
                                if ($Group_Member_Result.Count) {
                                    $Group_Member_To_Remove = @{
                                        'Path' = $Group_Member_Result.'adspath'
                                        'Name' = $($Group_Member_Result.'distinguishedname')
                                    }
                                    Write-Verbose ('{0}|Found group member: {1}' -f $Function_Name, $Group_Member_To_Remove['Name'])
                                    break
                                }
                            }
                            if (-not $Group_Member_To_Remove) {
                                $Terminating_ErrorRecord_Parameters = @{
                                    'Exception'    = 'System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException'
                                    'ID'           = 'DSS-{0}' -f $Function_Name
                                    'Category'     = 'ObjectNotFound'
                                    'TargetObject' = $Object_Directory_Entry
                                    'Message'      = 'Cannot find object with Identity of "{0}"' -f $Group_Member
                                }
                                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                            } else {
                                $Group_Members_To_Remove.Add($Group_Member_To_Remove)
                            }
                        }

                        $Remove_GroupMember_ShouldProcess = New-Object -TypeName 'System.Text.StringBuilder'
                        $Group_Members_To_Remove.GetEnumerator() | ForEach-Object {
                            [void]$Remove_GroupMember_ShouldProcess.AppendLine(('Remove group member "{0}" from target: "{1}".' -f $_['Name'], $($Object_Directory_Entry.'distinguishedname')))
                        }
                        $Whatif_Statement = $Remove_GroupMember_ShouldProcess.ToString().Trim()
                        $Confirm_Statement = $Whatif_Statement

                        if ($PSCmdlet.ShouldProcess($Whatif_Statement, $Confirm_Statement, $Confirm_Header.ToString())) {
                            Write-Verbose ('{0}|Removing {1} group members' -f $Function_Name, $Group_Members_To_Remove.Count)
                            foreach ($Remove_Member in $Group_Members_To_Remove) {
                                # Remove-ADGroupMember does not return any output if any of the Members are not part of the group so we do the same here.
                                try {
                                    $Object_Directory_Entry.Remove($Remove_Member['Path'])
                                } catch [System.DirectoryServices.DirectoryServicesCOMException] {
                                    if ($_.Exception.Message -eq 'The server is unwilling to process the request. (Exception from HRESULT: 0x80072035)') {
                                        Write-Verbose ('{0}|Not actually a group member: {1}' -f $Function_Name, $Remove_Member['Name'])
                                    } else {
                                        throw
                                    }
                                }
                            }
                            Write-Verbose ('{0}|Group Members removed successfully' -f $Function_Name)
                        }
                    }

                    'Unlock' {
                        $Whatif_Statement = 'Performing the operation "Unlock" on target "{0}".' -f $($Object_Directory_Entry.'distinguishedname')
                        $Confirm_Statement = $Whatif_Statement
                        if ($PSCmdlet.ShouldProcess($Whatif_Statement, $Confirm_Statement, $Confirm_Header.ToString())) {
                            Write-Verbose ('{0}|Found object, attempting unlock' -f $Function_Name)
                            # Taken from jrv's answer here: https://social.technet.microsoft.com/Forums/lync/en-US/349c0b3e-f4d6-4a65-8218-60901488855e/getting-user-quotlockouttimequot-using-adsi-interface-or-other-method-not-using-module?forum=ITCG
                            if ($Object_Directory_Entry.ConvertLargeIntegerToInt64($Object_Directory_Entry.lockouttime.Value) -gt 0) {
                                Write-Verbose ('{0}|Account is Locked, unlocking' -f $Function_Name)
                                $Object_Directory_Entry.lockouttime.Value = 0
                                $Object_Directory_Entry.SetInfo()
                                Write-Verbose ('{0}|Unlock successful' -f $Function_Name)
                            } else {
                                Write-Verbose ('{0}|Account is already Unlocked, doing nothing' -f $Function_Name)
                            }
                        }
                    }
                }
            } catch [System.UnauthorizedAccessException] {
                $Terminating_ErrorRecord_Parameters = @{
                    'Exception'      = 'System.UnauthorizedAccessException'
                    'ID'             = 'DSS-{0}' -f $Function_Name
                    'Category'       = 'SecurityError'
                    'TargetObject'   = $Object_Directory_Entry
                    'Message'        = 'Insufficient access rights to perform the operation.'
                    'InnerException' = $_.Exception
                }
                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
            } catch [System.DirectoryServices.DirectoryServicesCOMException] {
                # This exception is thrown when a disabled account has an unsuitable password, or no password.
                # LDAP response here: https://ldapwiki.com/wiki/ERROR_PASSWORD_RESTRICTION
                # Microsoft Error Code: https://docs.microsoft.com/en-gb/windows/win32/debug/system-error-codes--1300-1699-
                if ($_.Exception.ExtendedError -eq 1325) {
                    $Terminating_ErrorRecord_Parameters = @{
                        'Exception'      = 'System.DirectoryServices.DirectoryServicesCOMException'
                        'ID'             = 'DSS-{0}' -f $Function_Name
                        'Category'       = 'SecurityError'
                        'TargetObject'   = $Object_Directory_Entry
                        'Message'        = 'Failed to enable account due to password not meeting requirements.'
                        'InnerException' = $_.Exception
                    }
                    $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                    $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                } else {
                    throw
                }
            }
        } else {
            $Terminating_ErrorRecord_Parameters = @{
                'Exception'    = 'System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException'
                'ID'           = 'DSS-{0}' -f $Function_Name
                'Category'     = 'ObjectNotFound'
                'TargetObject' = $Object_Directory_Entry
                'Message'      = 'Cannot find object with {0} of "{1}"' -f $Directory_Search_Type, $Directory_Search_Value
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
