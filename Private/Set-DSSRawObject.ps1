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
        [ValidateSet(
            'AddGroupMember',
            'AddPrincipalGroupMembership',
            'Enable',
            'Disable',
            'RemoveObject',
            'RemoveGroupMember',
            'RemovePrincipalGroupMembership',
            'Unlock'
        )]
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

        # A group or list of groups to remove the object from.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $MemberOf,

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

        if ($SetType -match 'GroupMember') {
            Write-Verbose ('{0}|Getting GroupMembers or PrincipalGroups first' -f $Function_Name)
            $global:GroupMember_Objects = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'
            $GroupMember_Properties = @(
                'SAMAccountName'
                'DistinguishedName'
                'ObjectSID'
                'ObjectGUID'
            )

            if ($SetType -match 'PrincipalGroupMembership') {
                $Member_Set = $MemberOf
            } else {
                $Member_Set = $Members
            }

            foreach ($Member_Object in $Member_Set) {
                $Member_To_AddRemove = $null
                foreach ($GroupMember_Property in $GroupMember_Properties) {
                    if ($GroupMember_Property -eq 'ObjectGUID') {
                        # Only proceed if the $Member_Object string is a valid GUID.
                        if ([System.Guid]::TryParse($Member_Object, [ref][System.Guid]::Empty)) {
                            $Member_Object = (Convert-GuidToHex -Guid $Member_Object)
                        } else {
                            break
                        }
                    }
                    $Member_Search_Parameters = @{
                        'OutputFormat' = 'DirectoryEntry'
                        'LDAPFilter'   = ('({0}={1})' -f $GroupMember_Property, $Member_Object)
                    }
                    $Member_Object_Result = Find-DSSRawObject @Common_Search_Parameters @Member_Search_Parameters
                    if ($Member_Object_Result.Count) {
                        $Member_To_AddRemove = @{
                            'Path' = $Member_Object_Result.'adspath'
                            'Name' = $($Member_Object_Result.'distinguishedname')
                        }
                        if ($SetType -match 'PrincipalGroupMembership') {
                            $Member_To_AddRemove['Object'] = $Member_Object_Result
                        }
                        Write-Verbose ('{0}|Found member: {1}' -f $Function_Name, $Member_To_AddRemove['Name'])
                        break
                    }
                }
                if (-not $Member_To_AddRemove) {
                    $Terminating_ErrorRecord_Parameters = @{
                        'Exception'    = 'System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException'
                        'ID'           = 'DSS-{0}' -f $Function_Name
                        'Category'     = 'ObjectNotFound'
                        'TargetObject' = $Object_Directory_Entry
                        'Message'      = 'Cannot find object with Identity of "{0}"' -f $Member_Object
                    }
                    $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                    $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                } else {
                    $GroupMember_Objects.Add($Member_To_AddRemove)
                }
            }
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
                switch -Regex ($SetType) {
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

                    'GroupMember' {
                        $GroupMember_ShouldProcess = New-Object -TypeName 'System.Text.StringBuilder'
                        $GroupMember_Objects.GetEnumerator() | ForEach-Object {
                            if ($SetType -eq 'AddGroupMember') {
                                $ShouldProcess_Line = 'Add group member "{0}" to target: "{1}".' -f $_['Name'], $($Object_Directory_Entry.'distinguishedname')
                            } elseif ($SetType -eq 'AddPrincipalGroupMembership') {
                                $ShouldProcess_Line = 'Add target "{0}" to group: "{1}".' -f $($Object_Directory_Entry.'distinguishedname'), $_['Name']
                            } elseif ($SetType -eq 'RemoveGroupMember') {
                                $ShouldProcess_Line = 'Remove group member "{0}" from target: "{1}".' -f $_['Name'], $($Object_Directory_Entry.'distinguishedname')
                            } elseif ($SetType -eq 'RemovePrincipalGroupMembership') {
                                $ShouldProcess_Line = 'Remove target "{0}" from group: "{1}".' -f $($Object_Directory_Entry.'distinguishedname'), $_['Name']
                            }
                            [void]$GroupMember_ShouldProcess.AppendLine($ShouldProcess_Line)
                        }
                        $Whatif_Statement = $GroupMember_ShouldProcess.ToString().Trim()
                        $Confirm_Statement = $Whatif_Statement

                        if ($PSCmdlet.ShouldProcess($Whatif_Statement, $Confirm_Statement, $Confirm_Header.ToString())) {
                            # The Microsoft Add/Remove cmdlets do not return any output if the group members to remove are not currently members, or if the group members to add are already members.
                            # So just do the same here (suppress the specific error that is returned).
                            foreach ($GroupMember_Object in $GroupMember_Objects) {
                                try {
                                    if ($SetType -eq 'AddGroupMember') {
                                        $Object_Directory_Entry.Add($GroupMember_Object['Path'])
                                    } elseif ($SetType -eq 'AddPrincipalGroupMembership') {
                                        $GroupMember_Object['Object'].Add($Object_Directory_Entry.'adspath')
                                    } elseif ($SetType -eq 'RemoveGroupMember') {
                                        $Object_Directory_Entry.Remove($GroupMember_Object['Path'])
                                    } elseif ($SetType -eq 'RemovePrincipalGroupMembership') {
                                        $GroupMember_Object['Object'].Remove($Object_Directory_Entry.'adspath')
                                    }
                                } catch [System.DirectoryServices.DirectoryServicesCOMException] {
                                    if ($_.Exception.Message -eq 'The server is unwilling to process the request. (Exception from HRESULT: 0x80072035)') {
                                        if ($SetType -eq 'RemoveGroupMember') {
                                            Write-Verbose ('{0}|Not actually a group member: {1}' -f $Function_Name, $GroupMember_Object['Name'])
                                        } elseif ($SetType -eq 'RemovePrincipalGroupMembership') {
                                            Write-Verbose ('{0}|Not actually member of group: {1}' -f $Function_Name, $GroupMember_Object['Name'])
                                        }
                                    } elseif ($_.Exception.Message -eq 'The object already exists. (Exception from HRESULT: 0x80071392)') {
                                        if ($SetType -eq 'AddGroupMember') {
                                            Write-Verbose ('{0}|Already a group member: {1}' -f $Function_Name, $GroupMember_Object['Name'])
                                        } elseif ($SetType -eq 'AddPrincipalGroupMembership') {
                                            Write-Verbose ('{0}|Already a member of group: {1}' -f $Function_Name, $GroupMember_Object['Name'])
                                        }
                                    } else {
                                        throw
                                    }
                                }
                            }
                            Write-Verbose ('{0}|Group membership set successfully' -f $Function_Name)
                        }
                    }

                    'RemoveObject' {
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
