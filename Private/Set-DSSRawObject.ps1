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
        https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule
        https://ldapwiki.com/wiki/GroupType
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
    $PSBoundParameters.GetEnumerator() | ForEach-Object {
        if ($_.Value -is [hashtable]) {
            $Value = ($_.Value.GetEnumerator() | ForEach-Object { '{0} = {1}' -f $_.Name, $_.Value }) -join ' ; '
        } else {
            $Value = $_.Value -join ' '
        }
        Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, $Value)
    }

    try {
        $Common_Parameters = @('Context', 'Server', 'Credential')
        $Common_Search_Parameters = @{ }
        foreach ($Parameter in $Common_Parameters) {
            if ($PSBoundParameters.ContainsKey($Parameter)) {
                $Common_Search_Parameters[$Parameter] = Get-Variable -Name $Parameter -ValueOnly
            }
        }

        if ($Action -match 'GroupMember') {
            Write-Verbose ('{0}|Getting GroupMembers or PrincipalGroups first' -f $Function_Name)
            if ($Action -match 'PrincipalGroupMembership') {
                $Member_Set = $MemberOf
            } else {
                $Member_Set = $Members
            }
            $global:GroupMember_Objects = Get-DSSResolvedObject @Common_Search_Parameters -InputSet $Member_Set
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
                        $UAC_AccountDisabledFlag = '0x02'
                        $UAC_Current_Value = $Object.InvokeGet('useraccountcontrol')
                        if (($UAC_Current_Value -band $UAC_AccountDisabledFlag) -eq $UAC_AccountDisabledFlag) {
                            Write-Verbose ('{0}|Account is Disabled, enabling' -f $Function_Name)
                            $Object.Put('useraccountcontrol', ($UAC_Current_Value -bxor $UAC_AccountDisabledFlag))
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
                        $UAC_AccountDisabledFlag = '0x02'
                        $UAC_Current_Value = $Object.InvokeGet('useraccountcontrol')
                        if (($UAC_Current_Value -band $UAC_AccountDisabledFlag) -ne $UAC_AccountDisabledFlag) {
                            Write-Verbose ('{0}|Account is Enabled, disabling' -f $Function_Name)
                            $Object.Put('useraccountcontrol', ($UAC_Current_Value -bxor $UAC_AccountDisabledFlag))
                            $Object.SetInfo()
                            Write-Verbose ('{0}|Disable successful' -f $Function_Name)
                        } else {
                            Write-Verbose ('{0}|Account is already Disabled, doing nothing' -f $Function_Name)
                        }
                    }
                }

                'GroupMember' {
                    $GroupMember_ShouldProcess = New-Object -TypeName 'System.Text.StringBuilder'
                    foreach ($GroupMember_Object in $GroupMember_Objects) {
                        if ($Action -eq 'AddGroupMember') {
                            $ShouldProcess_Line = 'Add group member "{0}" to target: "{1}".' -f $GroupMember_Object['Name'], $($Object.'distinguishedname')
                        } elseif ($Action -eq 'AddPrincipalGroupMembership') {
                            $ShouldProcess_Line = 'Add target "{0}" to group: "{1}".' -f $($Object.'distinguishedname'), $GroupMember_Object['Name']
                        } elseif ($Action -eq 'RemoveGroupMember') {
                            $ShouldProcess_Line = 'Remove group member "{0}" from target: "{1}".' -f $GroupMember_Object['Name'], $($Object.'distinguishedname')
                        } elseif ($Action -eq 'RemovePrincipalGroupMembership') {
                            $ShouldProcess_Line = 'Remove target "{0}" from group: "{1}".' -f $($Object.'distinguishedname'), $GroupMember_Object['Name']
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
                    $Calculated_SubProperties_List = $Useful_Calculated_SubProperties.GetEnumerator() | ForEach-Object { $_.Value.GetEnumerator().Name }
                    $Set_Alias_Properties_Full = $Set_Alias_Properties.Values | ForEach-Object { $_ } # This will unwind any nested arrays
                    $Calculated_SubProperties_List_Full = $Calculated_SubProperties_List + $Set_Alias_Properties_Full

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
                        # The Country property needs to be handled separately, as it actually sets 3 LDAP properties.
                        if ($Replace.Keys -contains 'c') {
                            $Country_Property = $Replace['c']
                            if (($Countries_Ambiguous_Alpha2 -contains $Country_Property) -or ($Countries_Ambiguous_CountryCodes -contains $Country_Property)) {
                                $Terminating_ErrorRecord_Parameters = @{
                                    'Exception'    = 'Microsoft.ActiveDirectory.Management.ADException'
                                    'ID'           = 'DSS-{0}' -f $Function_Name
                                    'Category'     = 'InvalidData'
                                    'TargetObject' = $Object
                                    'Message'      = 'The specified country code "{0}" can apply to multiple country names. Please supply full country name instead.' -f $Country_Property
                                }
                                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                            } elseif (($Countries_Fullnames -notcontains $Country_Property) -and ($Countries_Alpha2 -notcontains $Country_Property) -and ($Countries_CountryCodes -notcontains $Country_Property)) {
                                $Terminating_ErrorRecord_Parameters = @{
                                    'Exception'    = 'System.ArgumentException'
                                    'ID'           = 'DSS-{0}' -f $Function_Name
                                    'Category'     = 'InvalidData'
                                    'TargetObject' = $Object
                                    'Message'      = 'The specified country "{0}" cannot be matched to a full country name or country code.' -f $Country_Property
                                }
                                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                            } else {
                                if ($Countries_Fullnames -contains $Country_Property) {
                                    $Country_FullName = $Property
                                } elseif ($Countries_Alpha2 -contains $Country_Property) {
                                    $Country_FullName = ($Countries.GetEnumerator() | Where-Object { $_.Value.'Alpha2' -eq $Country_Property }).Name
                                } elseif ($Countries_CountryCodes -contains $Country_Property) {
                                    $Country_FullName = ($Countries.GetEnumerator() | Where-Object { $_.Value.'CountryCode' -eq $Country_Property }).Name
                                }

                                $Replace['co'] = $Country_FullName
                                $Replace['c'] = $Countries[$Country_FullName]['Alpha2']
                                $Replace['countrycode'] = $Countries[$Country_FullName]['CountryCode']
                            }
                        }
                        if ($Replace.Keys -contains 'manager') {
                            Write-Verbose ('{0}|Resolving manager "{1}" to DistinguishedName' -f $Function_Name, $Replace['manager'])
                            $Resolved_Manager = Get-DSSResolvedObject @Common_Search_Parameters -InputSet $Replace['manager']
                            $Replace['manager'] = $Resolved_Manager.'Name'
                        }
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
                        if ($Calculated_SubProperties_List_Full -notcontains $Property) {
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
                    }

                    $Whatif_Statement = $Set_ShouldProcess.ToString().Trim()
                    $Confirm_Statement = $Whatif_Statement
                    if ($PSCmdlet.ShouldProcess($Whatif_Statement, $Confirm_Statement, $Confirm_Header.ToString())) {
                        $ADS_PROPERTY_CLEAR = 1
                        $ADS_PROPERTY_UPDATE = 2
                        $ADS_PROPERTY_APPEND = 3
                        $ADS_PROPERTY_DELETE = 4

                        if ($Remove) {
                            foreach ($Property in $Remove.GetEnumerator()) {
                                Write-Verbose ('{0}|Remove: "{1}" removed from "{2}"' -f $Function_Name, ($Property.Value -join ','), $Property.Name)
                                $Object.PutEx($ADS_PROPERTY_DELETE, $Property.Name, @($Property.Value))
                            }
                        }

                        if ($Add) {
                            foreach ($Property in $Add.GetEnumerator()) {
                                Write-Verbose ('{0}|Add: "{1}" added to "{2}"' -f $Function_Name, ($Property.Value -join ','), $Property.Name)
                                $Object.PutEx($ADS_PROPERTY_APPEND, $Property.Name, @($Property.Value))
                            }
                        }

                        if ($Replace) {
                            foreach ($Property in $Replace.GetEnumerator()) {
                                Write-Verbose ('{0}|Checking property: {1}' -f $Function_Name, $Property.Name)
                                if ($Calculated_SubProperties_List -contains $Property.Name) {
                                    $Parent_SubProperty = $Useful_Calculated_SubProperties.GetEnumerator() | Where-Object { $_.Value.GetEnumerator().Name -eq $Property.Name }
                                    $SubProperty_Name = $Parent_SubProperty.Name
                                    $SubProperty_Flag = $Parent_SubProperty.Value.$($Property.Name)
                                    $Current_Property_Value = $Object.InvokeGet($SubProperty_Name)
                                    # If the property name is "Enabled", then reverse the flag check, as the flag on UserAccountControl is actually a "Disabled" flag.
                                    if ($Property.Name -eq 'Enabled') {
                                        $SubProperty_Check = ($Current_Property_Value -band $SubProperty_Flag) -ne $SubProperty_Flag
                                    } else {
                                        $SubProperty_Check = ($Current_Property_Value -band $SubProperty_Flag) -eq $SubProperty_Flag
                                    }
                                    if ((($Property.Value -eq $true) -and -not $SubProperty_Check) -or (($Property.Value -eq $false) -and $SubProperty_Check)) {
                                        $Updated_Property = $Current_Property_Value -bxor $SubProperty_Flag
                                        Write-Verbose ('{0}|Setting "{1}" to: {2}' -f $Function_Name, $Property.Name, $Property.Value)
                                        Write-Verbose ('{0}| - Changing "{1}" from {2} to {3}' -f $Function_Name, $SubProperty_Name, $Current_Property_Value, $Updated_Property)
                                        $Object.Put($SubProperty_Name, $Updated_Property)
                                    } else {
                                        Write-Verbose ('{0}|Property already set correctly: {1}' -f $Function_Name, $SubProperty_Name)
                                    }

                                } elseif ($Property.Name -eq 'cannotchangepassword') {
                                    if ($Property.Value -isnot [boolean]) {
                                        $Terminating_ErrorRecord_Parameters = @{
                                            'Exception'      = 'System.ArgumentException'
                                            'ID'             = 'DSS-{0}' -f $Function_Name
                                            'Category'       = 'InvalidType'
                                            'TargetObject'   = $Object
                                            'Message'        = 'Specified property must be a boolean: {0}' -f $Property.Name
                                            'InnerException' = $_.Exception
                                        }
                                        $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                                        $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                                    }

                                    # This requires 2 Deny permissions to be set: the "Everyone" group and "NT AUTHORITY\SELF" user. Only if both are set to Deny, will "cannotchangepassword" be true.
                                    # Adapted from: https://social.technet.microsoft.com/Forums/scriptcenter/en-US/e947d590-d183-46b9-9a7a-4e785638c6fb/how-can-i-get-a-list-of-active-directory-user-accounts-where-the-user-cannot-change-the-password?forum=ITCG
                                    $ChangePassword_Rules = $Object.ObjectSecurity.Access | Where-Object { $_.ObjectType -eq $ChangePassword_GUID }
                                    $null = $ChangePassword_Identity_Everyone_Correct = $ChangePassword_Identity_Self_Correct

                                    if ($Property.Value -eq $true) {
                                        foreach ($ChangePassword_Rule in $ChangePassword_Rules) {
                                            if (($ChangePassword_Rule.IdentityReference -eq $ChangePassword_Identity_Everyone_Object) -and ($ChangePassword_Rule.AccessControlType -eq 'Deny')) {
                                                Write-Verbose ('{0}|CannotChangePassword: Found correct DENY permission for "Everyone" group: {1}' -f $Function_Name, $ChangePassword_Identity_Everyone_Object.Value)
                                                $ChangePassword_Identity_Everyone_Correct = $true
                                            }
                                            if (($ChangePassword_Rule.IdentityReference -eq $ChangePassword_Identity_Self_Object) -and ($ChangePassword_Rule.AccessControlType -eq 'Deny')) {
                                                Write-Verbose ('{0}|CannotChangePassword: Found correct DENY permission for "Self" user: {1}' -f $Function_Name, $ChangePassword_Identity_Self_Object.Value)
                                                $ChangePassword_Identity_Self_Correct = $true
                                            }
                                        }
                                        if ($ChangePassword_Identity_Everyone_Correct -and $ChangePassword_Identity_Self_Correct) {
                                            $ChangePassword_Action = 'None'
                                        } else {
                                            $ChangePassword_Action = 'SetDeny'
                                        }
                                    } elseif ($Property.Value -eq $false) {
                                        # For the ALLOW rule:
                                        # 1. Either just "Everyone" group can be set to Allow and no "NT AUTHORITY\SELF" user rule exists.
                                        # 2. Both "Everyone" group and "NT AUTHORITY\SELF" user rules are set to Allow.
                                        foreach ($ChangePassword_Rule in $ChangePassword_Rules) {
                                            if ($ChangePassword_Rule.IdentityReference -eq $ChangePassword_Identity_Everyone_Object) {
                                                if ($ChangePassword_Rule.AccessControlType -eq 'Allow') {
                                                    Write-Verbose ('{0}|CannotChangePassword: Found correct ALLOW permission for "Everyone" group: {1}' -f $Function_Name, $ChangePassword_Identity_Everyone_Object.Value)
                                                    $ChangePassword_Identity_Everyone_Correct = $true
                                                } else {
                                                    Write-Verbose ('{0}|CannotChangePassword: Found incorrect permission for "Everyone" group: {1}' -f $Function_Name, $ChangePassword_Identity_Everyone_Object.Value)
                                                    $ChangePassword_Identity_Everyone_Correct = $false
                                                }
                                            }
                                            if ($ChangePassword_Rule.IdentityReference -eq $ChangePassword_Identity_Self_Object) {
                                                if ($ChangePassword_Rule.AccessControlType -eq 'Allow') {
                                                    Write-Verbose ('{0}|CannotChangePassword: Found correct ALLOW permission for "Self" user: {1}' -f $Function_Name, $ChangePassword_Identity_Self_Object.Value)
                                                    $ChangePassword_Identity_Self_Correct = $true
                                                } else {
                                                    Write-Verbose ('{0}|CannotChangePassword: Found incorrect permission for "Self" user: {1} with permission "{2}"' -f $Function_Name, $ChangePassword_Identity_Self_Object.Value, $ChangePassword_Rule.AccessControlType)
                                                    $ChangePassword_Identity_Self_Correct = $false
                                                }
                                            }
                                        }
                                        if ($ChangePassword_Identity_Everyone_Correct -and ($ChangePassword_Identity_Self_Correct -ne $false)) {
                                            $ChangePassword_Action = 'None'
                                        } else {
                                            $ChangePassword_Action = 'SetAllow'
                                        }
                                    }

                                    switch ($ChangePassword_Action) {
                                        'SetAllow' {
                                            foreach ($ChangePassword_Rule in $ChangePassword_Rules) {
                                                [void]$Object.ObjectSecurity.RemoveAccessRule($ChangePassword_Rule)
                                            }
                                            Write-Verbose ('{0}|CannotChangePassword: Setting ALLOW permission for "Everyone" group: {1}' -f $Function_Name, $ChangePassword_Identity_Everyone_Object.Value)
                                            $ChangePassword_AccessRule_Arguments = @(
                                                $ChangePassword_Identity_Everyone_Object
                                                [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
                                                [System.Security.AccessControl.AccessControlType]::Allow
                                                [System.Guid]$ChangePassword_GUID
                                                [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
                                            )
                                            $ChangePassword_AccessRule = New-Object 'System.DirectoryServices.ActiveDirectoryAccessRule' -ArgumentList $ChangePassword_AccessRule_Arguments
                                            $Object.ObjectSecurity.SetAccessRule($ChangePassword_AccessRule)
                                            $Object.CommitChanges()
                                        }
                                        'SetDeny' {
                                            foreach ($ChangePassword_Rule in $ChangePassword_Rules) {
                                                [void]$Object.ObjectSecurity.RemoveAccessRule($ChangePassword_Rule)
                                            }
                                            $ChangePassword_AccessRule_Common = @(
                                                [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
                                                [System.Security.AccessControl.AccessControlType]::Deny
                                                [System.Guid]$ChangePassword_GUID
                                                [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
                                            )
                                            foreach ($ChangePassword_Identity in @($ChangePassword_Identity_Everyone_Object, $ChangePassword_Identity_Self_Object)) {
                                                Write-Verbose ('{0}|CannotChangePassword: Setting DENY permission for: {1}' -f $Function_Name, $ChangePassword_Identity.Value)
                                                $ChangePassword_AccessRule_Arguments = New-Object -TypeName 'System.Collections.Generic.List[Object]'
                                                $ChangePassword_AccessRule_Arguments.Add($ChangePassword_Identity)
                                                $ChangePassword_AccessRule_Arguments.AddRange($ChangePassword_AccessRule_Common)
                                                $ChangePassword_AccessRule = New-Object 'System.DirectoryServices.ActiveDirectoryAccessRule' -ArgumentList $ChangePassword_AccessRule_Arguments
                                                $Object.ObjectSecurity.SetAccessRule($ChangePassword_AccessRule)
                                                $Object.CommitChanges()
                                            }
                                        }
                                        'None' {
                                            Write-Verbose ('{0}|CannotChangePassword: Both permissions already set correctly, doing nothing' -f $Function_Name)
                                        }
                                    }

                                } else {
                                    if ($Set_Alias_Properties_Full -contains $Property.Name) {
                                        $Property_Name = ($Set_Alias_Properties.GetEnumerator() | Where-Object { $_.Value -eq $Property.Name }).Name
                                        $Current_Property_Value = $Object.InvokeGet($Property_Name)
                                        Write-Verbose ('{0}|Alias property name: {1}, Value: {2}' -f $Function_Name, $Property_Name, $Current_Property_Value)
                                        switch ($Property.Name) {
                                            # Delegation properties
                                            # Domain properties

                                            # Encryption properties
                                            'compoundidentitysupported' {
                                                $Compound_Identity_Value = $Additional_Encryption_Types.'Compound-Identity-Supported'
                                                if ($Property.Value -eq $true) {
                                                    $Compare_Value = $Current_Property_Value -bor $Compound_Identity_Value
                                                } else {
                                                    $Compare_Value = $Current_Property_Value -bxor $Compound_Identity_Value
                                                }
                                            }
                                            'kerberosencryptiontype' {
                                                $Compare_Value = ([Enum]::Parse('ADKerberosEncryptionType', ($Property.Value -join ', '), $true)).value__
                                            }

                                            # Group properties
                                            'groupcategory' {
                                                if ($Property.Value -eq 'Distribution') {
                                                    $Compare_Value = $Current_Property_Value -band -bnot $ADGroupTypes['Security']
                                                } elseif ($Property.Value -eq 'Security') {
                                                    $Compare_Value = $Current_Property_Value -bor $ADGroupTypes['Security']
                                                }
                                            }
                                            'groupscope' {
                                                if ($Current_Property_Value -le 0) {
                                                    $Compare_Base = -2147483648
                                                } else {
                                                    $Compare_Base = 0
                                                }
                                                $Compare_Value = $Compare_Base + $ADGroupTypes[$Property.Value]
                                            }

                                            # Security properties
                                            'changepasswordatlogon' {
                                                $Current_Property_Value = $Object.ConvertLargeIntegerToInt64($Object.'pwdlastset'.Value)
                                                if ($Property.Value -eq $true) {
                                                    $Compare_Value = 0
                                                } elseif ($Current_Property_Value -gt 0) {
                                                    $Compare_Value = $Current_Property_Value
                                                } else {
                                                    $Compare_Value = -1
                                                }
                                            }

                                            # Time properties
                                            # TimeSpan properties

                                            default {
                                                $Compare_Value = $Property.Value
                                            }
                                        }

                                    } else {
                                        $Property_Name = $Property.Name
                                        $Compare_Value = $Property.Value
                                        $Current_Property_Value = $Object.InvokeGet($Property.Name)
                                    }

                                    Write-Verbose ('{0}|Comparing "{1}" with "{2}"' -f $Function_Name, ($Current_Property_Value -join ','), ($Compare_Value -join ','))
                                    if ($Current_Property_Value -ne $Compare_Value) {
                                        # Check whether the groupscope conversion is possible:
                                        # https://docs.microsoft.com/en-us/windows/win32/ad/changing-a-groupampaposs-scope-or-type
                                        # Note: Even though the above page says no, the conversion "from Universal to DomainLocal if the Universal group is part of a DomainLocal from another domain" is possible. Works through Set-ADGroup too, so further testing may be needed.
                                        if ($Property_Name -eq 'grouptype') {
                                            Write-Verbose ('{0}|Getting group members and principal group membership' -f $Function_Name)
                                            $Error_Message = New-Object -TypeName 'System.Text.StringBuilder'
                                            $Common_Search_Parameters['Context'] = 'Forest'
                                            $Current_Group_Members = Get-DSSGroupMember @Common_Search_Parameters -DistinguishedName $Object.'distinguishedname' -Properties 'objectclass', 'groupscope', 'distinguishedname', 'domainname'
                                            $Current_Principal_Groups = Get-DSSPrincipalGroupMembership @Common_Search_Parameters -DistinguishedName $Object.'distinguishedname'

                                            if (($Current_Property_Value -bor $ADGroupTypes['Global']) -eq $Current_Property_Value) {
                                                if (($Compare_Value -bor $ADGroupTypes['Universal']) -eq $Compare_Value) {
                                                    Write-Verbose ('{0}|Converting Global to Universal' -f $Function_Name)
                                                    $Check_For_MemberOf_Global_Group = $Current_Principal_Groups | Where-Object { $_.'groupscope' -eq 'Global' }
                                                    if ($Check_For_MemberOf_Global_Group) {
                                                        [void]$Error_Message.AppendLine('Unable to convert group to Universal while a member of these Global groups:')
                                                        $Check_For_MemberOf_Global_Group.'distinguishedname' | ForEach-Object {
                                                            [void]$Error_Message.AppendLine($_)
                                                        }
                                                    }
                                                } elseif (($Compare_Value -bor $ADGroupTypes['DomainLocal']) -eq $Compare_Value) {
                                                    Write-Verbose ('{0}|Converting Global to DomainLocal' -f $Function_Name)
                                                    [void]$Error_Message.AppendLine('Unable to convert group from Global to Domain Local')
                                                }
                                            } elseif (($Current_Property_Value -bor $ADGroupTypes['DomainLocal']) -eq $Current_Property_Value) {
                                                if (($Compare_Value -bor $ADGroupTypes['Global']) -eq $Compare_Value) {
                                                    Write-Verbose ('{0}|Converting DomainLocal to Global' -f $Function_Name)
                                                    [void]$Error_Message.AppendLine('Unable to convert group from Domain Local to Global')
                                                } elseif (($Compare_Value -bor $ADGroupTypes['Universal']) -eq $Compare_Value) {
                                                    Write-Verbose ('{0}|Converting DomainLocal to Universal' -f $Function_Name)
                                                    Write-Verbose ('{0}|Checking for DomainLocal groups as members' -f $Function_Name)
                                                    $Check_For_DomainLocal_GroupMembers = $Current_Group_Members | Where-Object { $_.'groupscope' -eq 'Domain Local' }
                                                    if ($Check_For_DomainLocal_GroupMembers) {
                                                        [void]$Error_Message.AppendLine('Unable to convert group to Universal while these Domain Local groups are members:')
                                                        $Check_For_DomainLocal_GroupMembers.'distinguishedname' | ForEach-Object {
                                                            [void]$Error_Message.AppendLine($_)
                                                        }
                                                    }
                                                }
                                            } elseif (($Current_Property_Value -bor $ADGroupTypes['Universal']) -eq $Current_Property_Value) {
                                                $Current_Domain_Name = (Get-DSSGroup @Common_Search_Parameters -DistinguishedName $Object.'distinguishedname' -Properties 'domainname').'domainname'
                                                if (($Compare_Value -bor $ADGroupTypes['Global']) -eq $Compare_Value) {
                                                    Write-Verbose ('{0}|Converting Universal to Global' -f $Function_Name)
                                                    Write-Verbose ('{0}|Checking for Universal groups as members' -f $Function_Name)
                                                    $Check_For_Universal_GroupMembers = $Current_Group_Members | Where-Object { $_.'groupscope' -eq 'Universal' }
                                                    if ($Check_For_Universal_GroupMembers) {
                                                        [void]$Error_Message.AppendLine('Unable to convert group to Global while these Universal groups are members:')
                                                        $Check_For_Universal_GroupMembers.'distinguishedname' | ForEach-Object {
                                                            [void]$Error_Message.AppendLine($_)
                                                        }
                                                    }
                                                    Write-Verbose ('{0}|Checking for Users from another domain as members' -f $Function_Name)
                                                    $Check_For_OtherDomain_Users_GroupMembers = $Current_Group_Members | Where-Object { ($_.'objectclass' -contains 'User') -and ($_.'domainname' -ne $Current_Domain_Name) }
                                                    if ($Check_For_OtherDomain_Users_GroupMembers) {
                                                        [void]$Error_Message.AppendLine('Unable to convert group to Global while these users from a different domain are members:')
                                                        $Check_For_OtherDomain_Users_GroupMembers.'distinguishedname' | ForEach-Object {
                                                            [void]$Error_Message.AppendLine($_)
                                                        }
                                                    }
                                                    Write-Verbose ('{0}|Checking for Global groups from another domain as members' -f $Function_Name)
                                                    $Check_For_OtherDomain_Global_GroupMembers = $Current_Group_Members | Where-Object { ($_.'groupscope' -eq 'Global') -and ($_.'domainname' -ne $Current_Domain_Name) }
                                                    if ($Check_For_OtherDomain_Global_GroupMembers) {
                                                        [void]$Error_Message.AppendLine('Unable to convert group to Global while these Global groups from a different domain are members:')
                                                        $Check_For_OtherDomain_Global_GroupMembers.'distinguishedname' | ForEach-Object {
                                                            [void]$Error_Message.AppendLine($_)
                                                        }
                                                    }
                                                } elseif (($Compare_Value -bor $ADGroupTypes['DomainLocal']) -eq $Compare_Value) {
                                                    Write-Verbose ('{0}|Converting Universal to DomainLocal' -f $Function_Name)
                                                    $Check_For_MemberOf_Universal_Group = $Current_Principal_Groups | Where-Object { $_.'groupscope' -eq 'Universal' }
                                                    if ($Check_For_MemberOf_Universal_Group) {
                                                        [void]$Error_Message.AppendLine('Unable to convert group to Domain Local while a member of these Universal groups:')
                                                        $Check_For_MemberOf_Universal_Group.'distinguishedname' | ForEach-Object {
                                                            [void]$Error_Message.AppendLine($_)
                                                        }
                                                    }
                                                }
                                            }

                                            if ($Error_Message.Length) {
                                                $Terminating_ErrorRecord_Parameters = @{
                                                    'Exception'      = 'Microsoft.ActiveDirectory.Management.ADException'
                                                    'ID'             = 'DSS-{0}' -f $Function_Name
                                                    'Category'       = 'InvalidOperation'
                                                    'TargetObject'   = $Object
                                                    'Message'        = $Error_Message.ToString()
                                                    'InnerException' = $_.Exception
                                                }
                                                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                                                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                                            }
                                        }

                                        Write-Verbose ('{0}|Replace: "{1}" with "{2}"' -f $Function_Name, $Property_Name, ($Compare_Value -join ','))
                                        $Object.PutEx($ADS_PROPERTY_UPDATE, $Property_Name, @($Compare_Value))
                                    } else {
                                        Write-Verbose ('{0}|Property already set correctly: {1}' -f $Function_Name, $Property_Name)
                                    }
                                }
                            }
                        }

                        if ($Clear) {
                            foreach ($Property in $Clear) {
                                Write-Verbose ('{0}|Clear property: {1}' -f $Function_Name, $Property)
                                $Object.PutEx($ADS_PROPERTY_CLEAR, $Property, @())
                            }
                        }

                        Write-Verbose ('{0}|Applying properties on object' -f $Function_Name)
                        $Object.SetInfo()
                        Write-Verbose ('{0}|Properties applied successfully' -f $Function_Name)
                    }
                }

                'RemoveObject' {
                    $Whatif_Statement = 'Performing the operation "Remove" on target "{0}".' -f $($Object.'distinguishedname')
                    $Confirm_Statement = $Whatif_Statement
                    if ($PSCmdlet.ShouldProcess($Whatif_Statement, $Confirm_Statement, $Confirm_Header.ToString())) {
                        Write-Verbose ('{0}|Found object, checking for ProtectFromAccidentalDeletion' -f $Function_Name)
                        $Check_Object = Get-DSSObject @Common_Search_Parameters -DistinguishedName $Object.distinguishedname -Properties 'protectedfromaccidentaldeletion'
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
