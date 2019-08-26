function Set-DSSRawObject {
    <#
    .SYNOPSIS
        Make a modification to a specific object from Active Directory.
    .DESCRIPTION
        Performs the required modification to the object that is passed in via the $Object parameter.

        This is not meant to be used as an interactive function; it is used as a worker function by many of the other higher-level functions.
    .EXAMPLE
        $FindObject = Find-DSSRawObject -LDAPFilter '(objectsid=S-1-5-21-3515480276-2049723633-1306762111-1103)' -OutputFormat 'DirectoryEntry'
        Set-DSSRawObject -Action Remove -Object $FindObject

        Removes (deletes) the object with the above SID.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/remove-adobject
        https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.directoryentry
        https://docs.microsoft.com/en-us/windows/win32/api/iads/nf-iads-iadsgroup-remove
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.cmdlet.shouldprocess
        https://docs.microsoft.com/en-gb/windows/win32/api/iads/nf-iads-iads-put
        http://www.selfadsi.org/write.htm
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        # The type of action to take on the supplied object.
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'AddGroupMember',
            'AddPrincipalGroupMembership',
            'Enable',
            'Disable',
            'RemoveObject',
            'RemoveGroupMember',
            'RemovePrincipalGroupMembership',
            'Set',
            'Unlock'
        )]
        [Alias('Type')]
        [String]
        $Action,

        # The Active Directory directory entry object to perform the modification on.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Object]
        $Object,

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

        # The values to remove from an existing property.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [HashTable]
        $Remove,

        # The values to add to an existing property.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [HashTable]
        $Add,

        # Values to use to replace the existing property.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [HashTable]
        $Replace,

        # An array of properties to clear.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Array]
        $Clear,

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
        $Common_Parameters = @('Context', 'Server', 'Credential')
        $Common_Search_Parameters = @{}
        foreach ($Parameter in $Common_Parameters) {
            if ($PSBoundParameters.ContainsKey($Parameter)) {
                $Common_Search_Parameters[$Parameter] = Get-Variable -Name $Parameter -ValueOnly
            }
        }

        if ($Action -match 'GroupMember') {
            Write-Verbose ('{0}|Getting GroupMembers or PrincipalGroups first' -f $Function_Name)
            $global:GroupMember_Objects = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'
            $GroupMember_Properties = @(
                'SAMAccountName'
                'DistinguishedName'
                'ObjectSID'
                'ObjectGUID'
            )

            if ($Action -match 'PrincipalGroupMembership') {
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
                        if ($Action -match 'PrincipalGroupMembership') {
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
                        'TargetObject' = $Object
                        'Message'      = 'Cannot find object with Identity of "{0}"' -f $Member_Object
                    }
                    $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                    $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                } else {
                    $GroupMember_Objects.Add($Member_To_AddRemove)
                }
            }
        }

        $Confirm_Header = New-Object -TypeName 'System.Text.StringBuilder'
        [void]$Confirm_Header.AppendLine('Confirm')
        [void]$Confirm_Header.AppendLine('Are you sure you want to perform this action?')

        try {
            switch -Regex ($Action) {
                'Enable' {
                    $Whatif_Statement = 'Performing the operation "Enable" on target "{0}".' -f $($Object.'distinguishedname')
                    $Confirm_Statement = $Whatif_Statement
                    if ($PSCmdlet.ShouldProcess($Whatif_Statement, $Confirm_Statement, $Confirm_Header.ToString())) {
                        Write-Verbose ('{0}|Found object, attempting enable' -f $Function_Name)
                        $UAC_AccountDisabled = '0x02'
                        if (($Object.useraccountcontrol.Value -band $UAC_AccountDisabled) -eq $UAC_AccountDisabled) {
                            Write-Verbose ('{0}|Account is Disabled, enabling' -f $Function_Name)
                            $Object.useraccountcontrol.Value = $Object.useraccountcontrol.Value -bxor $UAC_AccountDisabled
                            $Object.SetInfo()
                            Write-Verbose ('{0}|Enable successful' -f $Function_Name)
                        } else {
                            Write-Verbose ('{0}|Account is already Enabled, doing nothing' -f $Function_Name)
                        }
                    }
                }

                'Disable' {
                    $Whatif_Statement = 'Performing the operation "Disable" on target "{0}".' -f $($Object.'distinguishedname')
                    $Confirm_Statement = $Whatif_Statement
                    if ($PSCmdlet.ShouldProcess($Whatif_Statement, $Confirm_Statement, $Confirm_Header.ToString())) {
                        Write-Verbose ('{0}|Found object, attempting disable' -f $Function_Name)
                        $UAC_AccountDisabled = '0x02'
                        if (($Object.useraccountcontrol.Value -band $UAC_AccountDisabled) -ne $UAC_AccountDisabled) {
                            Write-Verbose ('{0}|Account is Enabled, disabling' -f $Function_Name)
                            $Object.useraccountcontrol.Value = $Object.useraccountcontrol.Value -bxor $UAC_AccountDisabled
                            $Object.SetInfo()
                            Write-Verbose ('{0}|Disable successful' -f $Function_Name)
                        } else {
                            Write-Verbose ('{0}|Account is already Disabled, doing nothing' -f $Function_Name)
                        }
                    }
                }

                'GroupMember' {
                    $GroupMember_ShouldProcess = New-Object -TypeName 'System.Text.StringBuilder'
                    $GroupMember_Objects.GetEnumerator() | ForEach-Object {
                        if ($Action -eq 'AddGroupMember') {
                            $ShouldProcess_Line = 'Add group member "{0}" to target: "{1}".' -f $_['Name'], $($Object.'distinguishedname')
                        } elseif ($Action -eq 'AddPrincipalGroupMembership') {
                            $ShouldProcess_Line = 'Add target "{0}" to group: "{1}".' -f $($Object.'distinguishedname'), $_['Name']
                        } elseif ($Action -eq 'RemoveGroupMember') {
                            $ShouldProcess_Line = 'Remove group member "{0}" from target: "{1}".' -f $_['Name'], $($Object.'distinguishedname')
                        } elseif ($Action -eq 'RemovePrincipalGroupMembership') {
                            $ShouldProcess_Line = 'Remove target "{0}" from group: "{1}".' -f $($Object.'distinguishedname'), $_['Name']
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
                                if ($Action -eq 'AddGroupMember') {
                                    $Object.Add($GroupMember_Object['Path'])
                                } elseif ($Action -eq 'AddPrincipalGroupMembership') {
                                    $GroupMember_Object['Object'].Add($Object.'adspath')
                                } elseif ($Action -eq 'RemoveGroupMember') {
                                    $Object.Remove($GroupMember_Object['Path'])
                                } elseif ($Action -eq 'RemovePrincipalGroupMembership') {
                                    $GroupMember_Object['Object'].Remove($Object.'adspath')
                                }
                            } catch [System.DirectoryServices.DirectoryServicesCOMException] {
                                if ($_.Exception.Message -eq 'The server is unwilling to process the request. (Exception from HRESULT: 0x80072035)') {
                                    if ($Action -eq 'RemoveGroupMember') {
                                        Write-Verbose ('{0}|Not actually a group member: {1}' -f $Function_Name, $GroupMember_Object['Name'])
                                    } elseif ($Action -eq 'RemovePrincipalGroupMembership') {
                                        Write-Verbose ('{0}|Not actually member of group: {1}' -f $Function_Name, $GroupMember_Object['Name'])
                                    }
                                } elseif ($_.Exception.Message -eq 'The object already exists. (Exception from HRESULT: 0x80071392)') {
                                    if ($Action -eq 'AddGroupMember') {
                                        Write-Verbose ('{0}|Already a group member: {1}' -f $Function_Name, $GroupMember_Object['Name'])
                                    } elseif ($Action -eq 'AddPrincipalGroupMembership') {
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

                'Set' {
                    $Set_ShouldProcess = New-Object -TypeName 'System.Text.StringBuilder'
                    $Set_AllProperties = New-Object -TypeName 'System.Collections.Generic.List[String]'
                    if ($Remove) {
                        $Remove.GetEnumerator() | ForEach-Object {
                            $ShouldProcess_Line = 'Removing value "{0}" from property: "{1}"' -f ($_.Value -join ','), $_.Name
                            $Set_AllProperties.Add($_.Name)
                            [void]$Set_ShouldProcess.AppendLine($ShouldProcess_Line)
                        }
                    }
                    if ($Add) {
                        $Add.GetEnumerator() | ForEach-Object {
                            $ShouldProcess_Line = 'Adding value "{0}" to property: "{1}"' -f ($_.Value -join ','), $_.Name
                            $Set_AllProperties.Add($_.Name)
                            [void]$Set_ShouldProcess.AppendLine($ShouldProcess_Line)
                        }
                    }
                    if ($Replace) {
                        $Replace.GetEnumerator() | ForEach-Object {
                            $ShouldProcess_Line = 'Replace value of property "{0}" with value: "{1}"' -f $_.Name, ($_.Value -join ',')
                            $Set_AllProperties.Add($_.Name)
                            [void]$Set_ShouldProcess.AppendLine($ShouldProcess_Line)
                        }
                    }
                    if ($Clear) {
                        $Clear | ForEach-Object {
                            $ShouldProcess_Line = 'Clear value of property "{0}"' -f $_
                            $Set_AllProperties.Add($_)
                            [void]$Set_ShouldProcess.AppendLine($ShouldProcess_Line)
                        }
                    }

                    # Check that all properties are valid before attempting to modify any of them.
                    foreach ($Property in $Set_AllProperties) {
                        try {
                            $null = $Object.InvokeGet($Property)
                        } catch {
                            $Terminating_ErrorRecord_Parameters = @{
                                'Exception'      = 'System.ArgumentException'
                                'ID'             = 'DSS-{0}' -f $Function_Name
                                'Category'       = 'InvalidArgument'
                                'TargetObject'   = $Object
                                'Message'        = 'The specified LDAP attribute does not exist: {0}' -f $Property
                                'InnerException' = $_.Exception
                            }
                            $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                        }
                    }

                    $Whatif_Statement = $Set_ShouldProcess.ToString().Trim()
                    $Confirm_Statement = $Whatif_Statement
                    if ($PSCmdlet.ShouldProcess($Whatif_Statement, $Confirm_Statement, $Confirm_Header.ToString())) {
                        $ADS_PROPERTY_CLEAR = 1
                        $ADS_PROPERTY_UPDATE = 2
                        $ADS_PROPERTY_APPEND = 3
                        $ADS_PROPERTY_DELETE = 4

                        if ($Remove) {
                            $Remove.GetEnumerator() | ForEach-Object {
                                Write-Verbose ('{0}|Remove: "{1}" removed from "{2}"' -f $Function_Name, ($_.Value -join ','), $_.Name)
                                $Object.PutEx($ADS_PROPERTY_DELETE, $_.Name, @($_.Value))
                            }
                        }
                        if ($Add) {
                            $Add.GetEnumerator() | ForEach-Object {
                                Write-Verbose ('{0}|Add: "{1}" to "{2}"' -f $Function_Name, ($_.Value -join ','), $_.Name)
                                $Object.PutEx($ADS_PROPERTY_APPEND, $_.Name, @($_.Value))
                            }
                        }
                        if ($Replace) {
                            $Replace.GetEnumerator() | ForEach-Object {
                                Write-Verbose ('{0}|Replace: "{1}" with "{2}"' -f $Function_Name, $_.Name, ($_.Value -join ','))
                                $Object.PutEx($ADS_PROPERTY_UPDATE, $_.Name, @($_.Value))
                            }
                        }
                        if ($Clear) {
                            $Clear | ForEach-Object {
                                Write-Verbose ('{0}|Clear property: {1}' -f $Function_Name, $_)
                                $Object.PutEx($ADS_PROPERTY_CLEAR, $_, @())
                            }
                        }
                        Write-Verbose ('{0}|Setting properties on object' -f $Function_Name)
                        $Object.SetInfo()
                        Write-Verbose ('{0}|Properties set successfully' -f $Function_Name)
                    }
                }

                'RemoveObject' {
                    $Whatif_Statement = 'Performing the operation "Remove" on target "{0}".' -f $($Object.'distinguishedname')
                    $Confirm_Statement = $Whatif_Statement
                    if ($PSCmdlet.ShouldProcess($Whatif_Statement, $Confirm_Statement, $Confirm_Header.ToString())) {
                        Write-Verbose ('{0}|Found object, checking for ProtectFromAccidentalDeletion' -f $Function_Name)
                        $Check_Object = Get-DSSObject -DistinguishedName $Object.distinguishedname -Properties 'protectedfromaccidentaldeletion'
                        if ($Check_Object.'protectedfromaccidentaldeletion') {
                            $Terminating_ErrorRecord_Parameters = @{
                                'Exception'    = 'System.UnauthorizedAccessException'
                                'ID'           = 'DSS-{0}' -f $Function_Name
                                'Category'     = 'SecurityError'
                                'TargetObject' = $Object
                                'Message'      = 'Object is Protected From Accidental Deletion. Remove protection before trying to delete this object.'
                            }
                            $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                        }
                        Write-Verbose ('{0}|Attempting delete' -f $Function_Name)
                        if ($Object.objectclass -contains 'Group') {
                            Write-Verbose ('{0}|Object is a group, getting parent OU first' -f $Function_Name)
                            $Group_Directory_Entry_Parent_OU = Get-DSSDirectoryEntry @Common_Search_Parameters -Path $Object.Parent
                            $Group_Directory_Entry_Parent_OU.Delete('Group', ('CN={0}' -f $Object.cn.Value))
                        } elseif ($Object.objectclass -contains 'OrganizationalUnit') {
                            Write-Verbose ('{0}|Object is an OU, checking for child objects' -f $Function_Name)
                            if (([array]$Object.Children) -and (-not $Recursive)) {
                                Write-Verbose ('{0}|Found child objects and Recursive switch not present, unable to delete' -f $Function_Name)
                                $Terminating_ErrorRecord_Parameters = @{
                                    'Exception'    = 'System.DirectoryServices.DirectoryServicesCOMException'
                                    'ID'           = 'DSS-{0}' -f $Function_Name
                                    'Category'     = 'InvalidOperation'
                                    'TargetObject' = $Object
                                    'Message'      = 'Failed to remove due to child objects existing.'
                                }
                                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                            } else {
                                Write-Verbose ('{0}|No child objects found, or Recursive switch passed, deleting' -f $Function_Name)
                                $Object.DeleteTree()
                            }
                        } else {
                            $Object.DeleteTree()
                        }
                        Write-Verbose ('{0}|Delete successful' -f $Function_Name)
                    }
                }

                'Unlock' {
                    $Whatif_Statement = 'Performing the operation "Unlock" on target "{0}".' -f $($Object.'distinguishedname')
                    $Confirm_Statement = $Whatif_Statement
                    if ($PSCmdlet.ShouldProcess($Whatif_Statement, $Confirm_Statement, $Confirm_Header.ToString())) {
                        Write-Verbose ('{0}|Found object, attempting unlock' -f $Function_Name)
                        if ($Object.lockouttime.Value) {
                            # Taken from jrv's answer here: https://social.technet.microsoft.com/Forums/lync/en-US/349c0b3e-f4d6-4a65-8218-60901488855e/getting-user-quotlockouttimequot-using-adsi-interface-or-other-method-not-using-module?forum=ITCG
                            if ($Object.ConvertLargeIntegerToInt64($Object.lockouttime.Value) -gt 0) {
                                Write-Verbose ('{0}|Account is Locked, unlocking' -f $Function_Name)
                                $Object.lockouttime.Value = 0
                                $Object.SetInfo()
                                Write-Verbose ('{0}|Unlock successful' -f $Function_Name)
                            } else {
                                Write-Verbose ('{0}|Account is already Unlocked, doing nothing' -f $Function_Name)
                            }
                        } else {
                            Write-Verbose ('{0}|Account has never been logged in, doing nothing' -f $Function_Name)
                        }
                    }
                }
            }
        } catch [System.UnauthorizedAccessException] {
            $Terminating_ErrorRecord_Parameters = @{
                'Exception'      = 'System.UnauthorizedAccessException'
                'ID'             = 'DSS-{0}' -f $Function_Name
                'Category'       = 'SecurityError'
                'TargetObject'   = $Object
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
                    'TargetObject'   = $Object
                    'Message'        = 'Failed to enable account due to password not meeting requirements.'
                    'InnerException' = $_.Exception
                }
                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
            } elseif ($_.Exception.ExtendedError -eq 8321) {
                # This exception is thrown when you attempt to add another value to a single-valued AD property.
                # Microsoft Error Code: https://docs.microsoft.com/en-gb/windows/win32/debug/system-error-codes--8200-8999-
                $Terminating_ErrorRecord_Parameters = @{
                    'Exception'      = 'System.DirectoryServices.DirectoryServicesCOMException'
                    'ID'             = 'DSS-{0}' -f $Function_Name
                    'Category'       = 'InvalidData'
                    'TargetObject'   = $Object
                    'Message'        = 'Multiple values were specified for an attribute that can have only one value.'
                    'InnerException' = $_.Exception
                }
                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
            } elseif ($_.Exception.ExtendedError -eq 8311) {
                # This exception is thrown when you attempt to clear a property that cannot be cleared, or you attempt to set a value with the incorrect type (eg. int into a string value).
                # Microsoft Error Code: https://docs.microsoft.com/en-gb/windows/win32/debug/system-error-codes--8200-8999-
                $Terminating_ErrorRecord_Parameters = @{
                    'Exception'      = 'System.DirectoryServices.DirectoryServicesCOMException'
                    'ID'             = 'DSS-{0}' -f $Function_Name
                    'Category'       = 'InvalidData'
                    'TargetObject'   = $Object
                    'Message'        = $_.Exception.Message
                    'InnerException' = $_.Exception
                }
                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
            } else {
                throw
            }
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
