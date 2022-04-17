function Set-DSSRawObject {
    <#
    .SYNOPSIS
        Make a modification to a specific object from Active Directory.
    .DESCRIPTION
        Performs the required modification to the object that is passed in via the $Object parameter.

        This is not meant to be used as an interactive function; it is used as a worker function by many of the other higher-level functions.
    .EXAMPLE
        $FindObject = Find-DSSRawObject -LDAPFilter '(objectsid=S-1-5-21-3515480276-2049723633-1306762111-1103)' -OutputFormat 'DirectoryEntry'
        Set-DSSRawObject -Action RemoveObject -Object $FindObject

        Removes (deletes) the object with the above SID.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/activedirectory/remove-adobject
        https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.directoryentry
        https://docs.microsoft.com/en-us/windows/win32/api/iads/nf-iads-iadsgroup-remove
        https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.cmdlet.shouldprocess
        https://docs.microsoft.com/en-gb/windows/win32/api/iads/nf-iads-iads-put
        http://www.selfadsi.org/write.htm
        https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule
        https://ldapwiki.com/wiki/GroupType
        http://www.rlmueller.net/AccountExpires.htm
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        # The type of action to take on the supplied object.
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'AddGroupMember',
            'AddPrincipalGroupMembership',
            'RemoveObject',
            'RemoveGroupMember',
            'RemovePrincipalGroupMembership',
            'Set'
        )]
        [Alias('Type')]
        [String]
        $Action,

        # The values to add to an existing property.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $Add,

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

        # The credential to use for access.
        [Parameter(Mandatory = $false)]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        # A group or list of groups to remove the object from.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $MemberOf,

        # A member or list of members to remove from the group.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('Member')]
        [String[]]
        $Members,

        # The Active Directory directory entry object to perform the modification on.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Object]
        $Object,

        # Delete all child objects recursively.
        [Parameter(Mandatory = $false)]
        [Switch]
        $Recursive,

        # The values to remove from an existing property.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $Remove,

        # Values to use to replace the existing property.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $Replace,

        # The server to connect to.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Server
    )

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object {
        if ($_.Value -is [Hashtable]) {
            $Value = ($_.Value.GetEnumerator() | ForEach-Object { '{0} = {1}' -f $_.Name, ($_.Value -join ' ') }) -join ' ; '
        } else {
            $Value = $_.Value -join ' '
        }
        Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, $Value)
    }

    try {
        $Common_Parameters = @('Context', 'Server', 'Credential')
        $Managed_Keys = @('managedby', 'manager')

        # These are some special properties where the values need to be resolved and manipulated before they can be written back.
        $Special_Resolved_Properties = @('principalsallowedtodelegatetoaccount', 'certificates')
        $Special_Resolved_Properties_List = @{}

        $Common_Search_Parameters = @{}
        foreach ($Parameter in $Common_Parameters) {
            if ($PSBoundParameters.ContainsKey($Parameter)) {
                $Common_Search_Parameters[$Parameter] = Get-Variable -Name $Parameter -ValueOnly
            }
        }

        $Confirm_Header = New-Object -TypeName 'System.Text.StringBuilder'
        [void]$Confirm_Header.AppendLine('Confirm')
        [void]$Confirm_Header.AppendLine('Are you sure you want to perform this action?')

        try {
            switch -Regex ($Action) {
                'GroupMember' {
                    Write-Verbose ('{0}|Getting GroupMembers or PrincipalGroups first' -f $Function_Name)
                    if ($Action -match 'PrincipalGroupMembership') {
                        $Member_Set = $MemberOf
                    } else {
                        $Member_Set = $Members
                    }
                    $GroupMember_Objects = Get-DSSResolvedObject @Common_Search_Parameters -InputSet $Member_Set

                    $GroupMember_ShouldProcess = New-Object -TypeName 'System.Text.StringBuilder'
                    foreach ($GroupMember_Object in $GroupMember_Objects) {
                        if ($Action -eq 'AddGroupMember') {
                            $ShouldProcess_Line = 'Add group member "{0}" to target: "{1}".' -f $GroupMember_Object['distinguishedname'], $($Object.'distinguishedname')
                        } elseif ($Action -eq 'AddPrincipalGroupMembership') {
                            $ShouldProcess_Line = 'Add target "{0}" to group: "{1}".' -f $($Object.'distinguishedname'), $GroupMember_Object['distinguishedname']
                        } elseif ($Action -eq 'RemoveGroupMember') {
                            $ShouldProcess_Line = 'Remove group member "{0}" from target: "{1}".' -f $GroupMember_Object['distinguishedname'], $($Object.'distinguishedname')
                        } elseif ($Action -eq 'RemovePrincipalGroupMembership') {
                            $ShouldProcess_Line = 'Remove target "{0}" from group: "{1}".' -f $($Object.'distinguishedname'), $GroupMember_Object['distinguishedname']
                        }
                        [void]$GroupMember_ShouldProcess.AppendLine($ShouldProcess_Line)
                    }

                    $Whatif_Statement = $GroupMember_ShouldProcess.ToString().Trim()
                    $Confirm_Statement = ('Are you sure you want to perform this action?', $Whatif_Statement) -join [Environment]::NewLine
                    if ($PSCmdlet.ShouldProcess($Whatif_Statement, $Confirm_Statement, 'Confirm')) {
                        # The Microsoft Add/Remove cmdlets do not return any output if the group members to remove are not currently members, or if the group members to add are already members.
                        # So just do the same here (suppress the specific error that is returned).
                        foreach ($GroupMember_Object in $GroupMember_Objects) {
                            try {
                                if ($Action -eq 'AddGroupMember') {
                                    $Object.Add($GroupMember_Object['adspath'])
                                } elseif ($Action -eq 'AddPrincipalGroupMembership') {
                                    $GroupMember_Object['Object'].Add($Object.'adspath')
                                } elseif ($Action -eq 'RemoveGroupMember') {
                                    $Object.Remove($GroupMember_Object['adspath'])
                                } elseif ($Action -eq 'RemovePrincipalGroupMembership') {
                                    $GroupMember_Object['Object'].Remove($Object.'adspath')
                                }
                            } catch [System.DirectoryServices.DirectoryServicesCOMException] {
                                if ($_.Exception.Message -eq 'The server is unwilling to process the request. (Exception from HRESULT: 0x80072035)') {
                                    if ($Action -eq 'RemoveGroupMember') {
                                        Write-Verbose ('{0}|Not actually a group member: {1}' -f $Function_Name, $GroupMember_Object['distinguishedname'])
                                    } elseif ($Action -eq 'RemovePrincipalGroupMembership') {
                                        Write-Verbose ('{0}|Not actually member of group: {1}' -f $Function_Name, $GroupMember_Object['distinguishedname'])
                                    }
                                } elseif ($_.Exception.Message -eq 'The object already exists. (Exception from HRESULT: 0x80071392)') {
                                    if ($Action -eq 'AddGroupMember') {
                                        Write-Verbose ('{0}|Already a group member: {1}' -f $Function_Name, $GroupMember_Object['distinguishedname'])
                                    } elseif ($Action -eq 'AddPrincipalGroupMembership') {
                                        Write-Verbose ('{0}|Already a member of group: {1}' -f $Function_Name, $GroupMember_Object['distinguishedname'])
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
                        $Remove.GetEnumerator() | Where-Object { $Special_Resolved_Properties -contains $_.Name } | ForEach-Object {
                            $Special_Resolved_Properties_List[$_.Name] += @{'Remove' = $_.Value }
                        }

                        $Remove.GetEnumerator() | ForEach-Object {
                            $ShouldProcess_Line = 'Removing value "{0}" from property: "{1}"' -f ($_.Value -join ','), $_.Name
                            $Set_AllProperties.Add($_.Name)
                            [void]$Set_ShouldProcess.AppendLine($ShouldProcess_Line)
                        }
                    }

                    if ($Add) {
                        $Add.GetEnumerator() | Where-Object { $Special_Resolved_Properties -contains $_.Name } | ForEach-Object {
                            $Special_Resolved_Properties_List[$_.Name] += @{'Add' = $_.Value }
                        }

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
                                    'Exception'    = 'System.ArgumentException'
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
                        foreach ($Managed_Key in $Managed_Keys) {
                            if ($Replace.Keys -contains $Managed_Key) {
                                Write-Verbose ('{0}|Resolving {1} "{2}" to DistinguishedName' -f $Function_Name, $Managed_Key, $Replace[$Managed_Key])
                                $Resolved_Key = Get-DSSResolvedObject @Common_Search_Parameters -InputSet $Replace[$Managed_Key]
                                $Replace[$Managed_Key] = $Resolved_Key.'distinguishedname'
                            }
                        }

                        $Replace.GetEnumerator() | Where-Object { $Special_Resolved_Properties -contains $_.Name } | ForEach-Object {
                            $Special_Resolved_Properties_List[$_.Name] += @{'Replace' = $_.Value }
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
                    $Confirm_Statement = ('Are you sure you want to perform this action?', $Whatif_Statement) -join [Environment]::NewLine
                    if ($PSCmdlet.ShouldProcess($Whatif_Statement, $Confirm_Statement, 'Confirm')) {
                        $ADS_PROPERTY_CLEAR = 1
                        $ADS_PROPERTY_UPDATE = 2
                        $ADS_PROPERTY_APPEND = 3
                        $ADS_PROPERTY_DELETE = 4

                        if ($Remove) {
                            foreach ($Property in ($Remove.GetEnumerator() | Where-Object { $Special_Resolved_Properties -notcontains $_.Name })) {
                                Write-Verbose ('{0}|Remove: "{1}" removed from "{2}"' -f $Function_Name, ($Property.Value -join ','), $Property.Name)
                                $Object.PutEx($ADS_PROPERTY_DELETE, $Property.Name, @($Property.Value))
                            }
                        }

                        if ($Add) {
                            foreach ($Property in ($Add.GetEnumerator() | Where-Object { $Special_Resolved_Properties -notcontains $_.Name })) {
                                Write-Verbose ('{0}|Add: "{1}" added to "{2}"' -f $Function_Name, ($Property.Value -join ','), $Property.Name)
                                $Object.PutEx($ADS_PROPERTY_APPEND, $Property.Name, @($Property.Value))
                            }
                        }

                        if ($Replace) {
                            foreach ($Property in ($Replace.GetEnumerator() | Where-Object { $Special_Resolved_Properties -notcontains $_.Name })) {
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
                                            if (($ChangePassword_Rule.IdentityReference -eq $Localised_Identity_Everyone_Object) -and ($ChangePassword_Rule.AccessControlType -eq 'Deny')) {
                                                Write-Verbose ('{0}|CannotChangePassword: Found correct DENY permission for "Everyone" group: {1}' -f $Function_Name, $Localised_Identity_Everyone_Object.Value)
                                                $ChangePassword_Identity_Everyone_Correct = $true
                                            }
                                            if (($ChangePassword_Rule.IdentityReference -eq $Localised_Identity_Self_Object) -and ($ChangePassword_Rule.AccessControlType -eq 'Deny')) {
                                                Write-Verbose ('{0}|CannotChangePassword: Found correct DENY permission for "Self" user: {1}' -f $Function_Name, $Localised_Identity_Self_Object.Value)
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
                                            if ($ChangePassword_Rule.IdentityReference -eq $Localised_Identity_Everyone_Object) {
                                                if ($ChangePassword_Rule.AccessControlType -eq 'Allow') {
                                                    Write-Verbose ('{0}|CannotChangePassword: Found correct ALLOW permission for "Everyone" group: {1}' -f $Function_Name, $Localised_Identity_Everyone_Object.Value)
                                                    $ChangePassword_Identity_Everyone_Correct = $true
                                                } else {
                                                    Write-Verbose ('{0}|CannotChangePassword: Found incorrect permission for "Everyone" group: {1}' -f $Function_Name, $Localised_Identity_Everyone_Object.Value)
                                                    $ChangePassword_Identity_Everyone_Correct = $false
                                                }
                                            }
                                            if ($ChangePassword_Rule.IdentityReference -eq $Localised_Identity_Self_Object) {
                                                if ($ChangePassword_Rule.AccessControlType -eq 'Allow') {
                                                    Write-Verbose ('{0}|CannotChangePassword: Found correct ALLOW permission for "Self" user: {1}' -f $Function_Name, $Localised_Identity_Self_Object.Value)
                                                    $ChangePassword_Identity_Self_Correct = $true
                                                } else {
                                                    Write-Verbose ('{0}|CannotChangePassword: Found incorrect permission for "Self" user: {1} with permission "{2}"' -f $Function_Name, $Localised_Identity_Self_Object.Value, $ChangePassword_Rule.AccessControlType)
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
                                        # Specific ActiveDirectoryAccessRule: https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=dotnet-plat-ext-3.1#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_System_Guid_System_DirectoryServices_ActiveDirectorySecurityInheritance_
                                        'SetAllow' {
                                            foreach ($ChangePassword_Rule in $ChangePassword_Rules) {
                                                [void]$Object.ObjectSecurity.RemoveAccessRule($ChangePassword_Rule)
                                            }
                                            Write-Verbose ('{0}|CannotChangePassword: Setting ALLOW permission for "Everyone" group: {1}' -f $Function_Name, $Localised_Identity_Everyone_Object.Value)
                                            $ChangePassword_AccessRule_Arguments = @(
                                                $Localised_Identity_Everyone_Object
                                                [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
                                                [System.Security.AccessControl.AccessControlType]::Allow
                                                [System.Guid]$ChangePassword_GUID
                                                [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
                                            )
                                            $ChangePassword_AccessRule = New-Object 'System.DirectoryServices.ActiveDirectoryAccessRule' -ArgumentList $ChangePassword_AccessRule_Arguments
                                            $Object.ObjectSecurity.SetAccessRule($ChangePassword_AccessRule)
                                            $Object.psbase.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
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
                                            foreach ($ChangePassword_Identity in @($Localised_Identity_Everyone_Object, $Localised_Identity_Self_Object)) {
                                                Write-Verbose ('{0}|CannotChangePassword: Setting DENY permission for: {1}' -f $Function_Name, $ChangePassword_Identity.Value)
                                                $ChangePassword_AccessRule_Arguments = New-Object -TypeName 'System.Collections.Generic.List[Object]'
                                                $ChangePassword_AccessRule_Arguments.Add($ChangePassword_Identity)
                                                $ChangePassword_AccessRule_Arguments.AddRange($ChangePassword_AccessRule_Common)
                                                $ChangePassword_AccessRule = New-Object 'System.DirectoryServices.ActiveDirectoryAccessRule' -ArgumentList $ChangePassword_AccessRule_Arguments
                                                $Object.ObjectSecurity.SetAccessRule($ChangePassword_AccessRule)
                                                $Object.psbase.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
                                                $Object.CommitChanges()
                                            }
                                        }
                                        'None' {
                                            Write-Verbose ('{0}|CannotChangePassword: Both permissions already set correctly, doing nothing' -f $Function_Name)
                                        }
                                    }

                                } elseif ($Property.Name -eq 'protectedfromaccidentaldeletion') {
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
                                    $AccidentalDeletion_Rule = $Object.ObjectSecurity.Access | Where-Object { ($_.ActiveDirectoryRights -match $AccidentalDeletion_Rights) -and ($_.IdentityReference -eq $Localised_Identity_Everyone_Object.Value) }

                                    if (($AccidentalDeletion_Rule.Count -eq 1) -and ($AccidentalDeletion_Rule.AccessControlType -eq 'Deny')) {
                                        Write-Verbose ('{0}|AccidentalDeletion: Found correct DENY permission' -f $Function_Name)
                                        if ($Property.Value -eq $true) {
                                            $AccidentalDeletion_Action = 'None'
                                        } elseif ($Property.Value -eq $false) {
                                            $AccidentalDeletion_Action = 'RemoveDeny'
                                        }
                                    } else {
                                        Write-Verbose ('{0}|AccidentalDeletion: Did not find DENY permission' -f $Function_Name)
                                        if ($Property.Value -eq $true) {
                                            $AccidentalDeletion_Action = 'SetDeny'
                                        } elseif ($Property.Value -eq $false) {
                                            $AccidentalDeletion_Action = 'None'
                                        }
                                    }

                                    switch ($AccidentalDeletion_Action) {
                                        'RemoveDeny' {
                                            Write-Verbose ('{0}|AccidentalDeletion: Removing DENY permission for "Everyone" group: {1}' -f $Function_Name, $Localised_Identity_Everyone_Object.Value)
                                            [void]$Object.ObjectSecurity.RemoveAccessRule($AccidentalDeletion_Rule)
                                            $Object.psbase.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
                                            $Object.CommitChanges()
                                        }
                                        'SetDeny' {
                                            # Specific ActiveDirectoryAccessRule: https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=dotnet-plat-ext-3.1#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_System_DirectoryServices_ActiveDirectorySecurityInheritance_
                                            Write-Verbose ('{0}|AccidentalDeletion: Setting DENY permission for "Everyone" group: {1}' -f $Function_Name, $Localised_Identity_Everyone_Object.Value)
                                            $AccidentalDeletion_AccessRule_Arguments = @(
                                                $Localised_Identity_Everyone_Object
                                                $AccidentalDeletion_Rights
                                                [System.Security.AccessControl.AccessControlType]::Deny
                                                [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
                                            )
                                            $AccidentalDeletion_AccessRule = New-Object 'System.DirectoryServices.ActiveDirectoryAccessRule' -ArgumentList $AccidentalDeletion_AccessRule_Arguments
                                            $Object.ObjectSecurity.SetAccessRule($AccidentalDeletion_AccessRule)
                                            $Object.psbase.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
                                            $Object.CommitChanges()
                                        }
                                        'None' {
                                            Write-Verbose ('{0}|AccidentalDeletion: Permission already set correctly, doing nothing' -f $Function_Name)
                                        }
                                    }

                                } elseif ($Property.Name -eq 'unlock') {
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

                                    $Object_LockoutTime = $Object.InvokeGet('lockouttime')
                                    if ($Object_LockoutTime) {
                                        if ($Object.ConvertLargeIntegerToInt64($Object_LockoutTime) -gt 0) {
                                            Write-Verbose ('{0}|Account is Locked, unlocking by settting "lockouttime" to 0' -f $Function_Name)
                                            $Object.Put('lockouttime', 0)
                                        } else {
                                            Write-Verbose ('{0}|Account is already Unlocked, doing nothing' -f $Function_Name)
                                        }
                                    } else {
                                        Write-Verbose ('{0}|Account has never been logged in, doing nothing' -f $Function_Name)
                                    }

                                } elseif ($Property.Name -eq 'accountexpirationdate') {
                                    if (($Property.Value -isnot [DateTime]) -and ($null -ne $Property.Value)) {
                                        $Terminating_ErrorRecord_Parameters = @{
                                            'Exception'      = 'System.ArgumentException'
                                            'ID'             = 'DSS-{0}' -f $Function_Name
                                            'Category'       = 'InvalidType'
                                            'TargetObject'   = $Object
                                            'Message'        = 'Specified property must be a DateTime: {0}' -f $Property.Name
                                            'InnerException' = $_.Exception
                                        }
                                        $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                                        $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                                    }

                                    if ($null -eq $Property.Value) {
                                        Write-Verbose ('{0}|Expiration date is null, will clear expiration date' -f $Function_Name)
                                        $Compare_Value = 0
                                    } else {
                                        $Compare_Value = $Property.Value.ToFileTime().ToString()
                                    }

                                    $Object_AccountExpirationDate = $Object.InvokeGet('accountexpirationdate')
                                    if ($Object_AccountExpirationDate -ne $Compare_Value) {
                                        Write-Verbose ('{0}|Setting "accountexpires" to: {1}' -f $Function_Name, $Compare_Value)
                                        $Object.Put('accountExpires', $Compare_Value)
                                    } else {
                                        Write-Verbose ('{0}|Value for "accountexpires" unchanged, doing nothing' -f $Function_Name, $Property.Value)
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
                                            $Current_Group_Members_Properties = @{
                                                'DistinguishedName'   = $Object.'distinguishedname'
                                                'Properties'          = @('distinguishedname', 'domainname', 'groupscope', 'objectclass')
                                                'NoDefaultProperties' = $true
                                            }
                                            $Current_Group_Members = Get-DSSGroupMember @Common_Search_Parameters @Current_Group_Members_Properties
                                            $Current_Principal_Groups_Properties = @{
                                                'DistinguishedName'   = $Object.'distinguishedname'
                                                'Properties'          = @('distinguishedname', 'groupscope')
                                                'NoDefaultProperties' = $true
                                            }
                                            $Current_Principal_Groups = Get-DSSPrincipalGroupMembership @Common_Search_Parameters @Current_Principal_Groups_Properties

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
                                                $Domain_Name_Search_Parameters = @{
                                                    'DistinguishedName'   = $Object.'distinguishedname'
                                                    'Properties'          = 'domainname'
                                                    'NoDefaultProperties' = $true
                                                }
                                                $Current_Domain_Name = (Get-DSSGroup @Common_Search_Parameters @Domain_Name_Search_Parameters).'domainname'
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

                                        Write-Verbose ('{0}|Replace: "{1}" with value "{2}"' -f $Function_Name, $Property_Name, ($Compare_Value -join ','))
                                        $Object.PutEx($ADS_PROPERTY_UPDATE, $Property_Name, @($Compare_Value))
                                    } else {
                                        Write-Verbose ('{0}|Property already set correctly: {1}' -f $Function_Name, $Property_Name)
                                    }
                                }
                            }
                        }

                        if ($Clear) {
                            $Clear | Where-Object { $Special_Resolved_Properties -contains $_ } | ForEach-Object {
                                $Special_Resolved_Properties_List[$_] += @{'Clear' = $_ }
                            }

                            foreach ($Property in ($Clear | Where-Object { $Special_Resolved_Properties -notcontains $_ })) {
                                if ($Combined_Calculated_Properties.Values -contains $Property) {
                                    $Property = ($Combined_Calculated_Properties.GetEnumerator() | Where-Object { $_.Value -eq $Current_Value }).'Name'
                                }
                                Write-Verbose ('{0}|Clear property: {1}' -f $Function_Name, $Property)
                                $Object.PutEx($ADS_PROPERTY_CLEAR, $Property, @())
                            }
                        }

                        if ($Special_Resolved_Properties_List.Count) {
                            Write-Verbose ('{0}|Processing special properties' -f $Function_Name)
                            foreach ($Property in $Special_Resolved_Properties_List.GetEnumerator()) {
                                Write-Verbose ('{0}|Special: Checking property: {1}' -f $Function_Name, $Property.Name)
                                if ($Property.Name -eq 'principalsallowedtodelegatetoaccount') {
                                    # References:
                                    # https://devblogs.microsoft.com/scripting/use-powershell-to-set-security-permissions-for-remoting/
                                    # http://www.gabescode.com/active-directory/2019/07/25/nt-security-descriptors.html
                                    #
                                    # It would be nice to get the 'msds-allowedtoactonbehalfofotheridentity' property directly from the $Object via $Object.InvokeGet('msds-allowedtoactonbehalfofotheridentity')
                                    # Doing this returns the property as a System.__ComObject, and I am not able to find a method to convert this COMObject into the byte array that is returned from a search
                                    # So will have to make another call to get this property in the correct format
                                    $Principal_Search_Parameters = @{
                                        'DistinguishedName'   = $Object.InvokeGet('distinguishedname')
                                        'NoDefaultProperties' = $true
                                        'Properties'          = 'msds-allowedtoactonbehalfofotheridentity'
                                    }
                                    $Principal_Search = Get-DSSComputer @Common_Search_Parameters @Principal_Search_Parameters
                                    $Existing_Rules = $Principal_Search.'msds-allowedtoactonbehalfofotheridentity'
                                    # If msds-allowedtoactonbehalfofotheridentity has never been set, it will be null, so set it as a blank ActiveDirectorySecurity object, then we can add to it.
                                    if ($Existing_Rules -isnot [System.DirectoryServices.ActiveDirectorySecurity]) {
                                        $Existing_Rules = New-Object -TypeName 'System.DirectoryServices.ActiveDirectorySecurity'
                                        $Existing_Rules.SetSecurityDescriptorSddlForm('O:BAD:') # Sets BUILTIN\Administrators as the owner.
                                    }

                                    # If there is a Clear or Replace value, simply ignore Add and Remove.
                                    if ($Special_Resolved_Properties_List[$Property.Name]['Clear']) {
                                        Write-Verbose ('{0}|Special {1}: Clear: Removing all existing rules' -f $Function_Name, $Property.Name)
                                        $Object.PutEx($ADS_PROPERTY_CLEAR, 'msds-allowedtoactonbehalfofotheridentity', @())
                                    } elseif ($Special_Resolved_Properties_List[$Property.Name]['Replace']) {
                                        # Remove all current rules first, then add all the specified computers.
                                        Write-Verbose ('{0}|Special {1}: Replace: Removing all existing rules' -f $Function_Name, $Property.Name)
                                        $Existing_Rules.Access | ForEach-Object { [void]$Existing_Rules.RemoveAccessRule($_) }
                                        Get-DSSResolvedObject @Common_Search_Parameters -InputSet $Special_Resolved_Properties_List[$Property.Name]['Replace'] | ForEach-Object {
                                            $Delegation_AccessRule_Arguments = @(
                                                [System.Security.Principal.IdentityReference] $_.'objectsid'
                                                [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                                                [System.Security.AccessControl.AccessControlType]::Allow
                                            )
                                            $Delegation_AccessRule = New-Object 'System.DirectoryServices.ActiveDirectoryAccessRule' -ArgumentList $Delegation_AccessRule_Arguments
                                            Write-Verbose ('{0}|Special {1}: Replace: Adding computer: {2}' -f $Function_Name, $Property.Name, $_.'distinguishedname')
                                            [void]$Existing_Rules.AddAccessRule($Delegation_AccessRule)
                                        }
                                        Write-Verbose ('{0}|Special {1}: Replace: Setting "msds-allowedtoactonbehalfofotheridentity"' -f $Function_Name, $Property.Name)
                                        $Object.Put('msds-allowedtoactonbehalfofotheridentity', $Existing_Rules.GetSecurityDescriptorBinaryForm())
                                    } else {
                                        if ($Special_Resolved_Properties_List[$Property.Name]['Remove']) {
                                            Write-Verbose ('{0}|Special {1}: Remove: Resolving computer: {2}' -f $Function_Name, $Property.Name, $Special_Resolved_Properties_List[$Property.Name]['Remove'])
                                            Get-DSSResolvedObject @Common_Search_Parameters -InputSet $Special_Resolved_Properties_List[$Property.Name]['Remove'] | ForEach-Object {
                                                foreach ($Existing_Rule in $Existing_Rules.Access) {
                                                    $Computer_Domain, $Computer_Name = $Existing_Rule.IdentityReference.Value.Split('\')
                                                    $Computer_SID = [System.Security.Principal.NTAccount]::New($Computer_Domain, $Computer_Name).Translate([System.Security.Principal.SecurityIdentifier]).Value
                                                    if ($Computer_SID -eq $_.'objectsid'.Value) {
                                                        Write-Verbose ('{0}|Special {1}: Remove: Removing computer: {2}\{3}' -f $Function_Name, $Property.Name, $Computer_Domain, $Computer_Name)
                                                        [void]$Existing_Rules.RemoveAccessRule($Existing_Rule)
                                                        $Rule_Removed = $true
                                                    }
                                                }
                                            }
                                            if ($Rule_Removed) {
                                                Write-Verbose ('{0}|Special {1}: Remove: Setting "msds-allowedtoactonbehalfofotheridentity"' -f $Function_Name, $Property.Name)
                                                $Object.Put('msds-allowedtoactonbehalfofotheridentity', $Existing_Rules.GetSecurityDescriptorBinaryForm())
                                            }
                                        }
                                        if ($Special_Resolved_Properties_List[$Property.Name]['Add']) {
                                            Write-Verbose ('{0}|Special {1}: Add: Resolving computer: {2}' -f $Function_Name, $Property.Name, $Special_Resolved_Properties_List[$Property.Name]['Add'])
                                            Get-DSSResolvedObject @Common_Search_Parameters -InputSet $Special_Resolved_Properties_List[$Property.Name]['Add'] | ForEach-Object {
                                                $Delegation_AccessRule_Arguments = @(
                                                    [System.Security.Principal.IdentityReference] $_.'objectsid'
                                                    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                                                    [System.Security.AccessControl.AccessControlType]::Allow
                                                )
                                                $Delegation_AccessRule = New-Object 'System.DirectoryServices.ActiveDirectoryAccessRule' -ArgumentList $Delegation_AccessRule_Arguments
                                                Write-Verbose ('{0}|Special {1}: Add: Adding computer: {2}' -f $Function_Name, $Property.Name, $_.'distinguishedname')
                                                [void]$Existing_Rules.AddAccessRule($Delegation_AccessRule)
                                            }
                                            Write-Verbose ('{0}|Special {1}: Add: Setting "msds-allowedtoactonbehalfofotheridentity"' -f $Function_Name, $Property.Name)
                                            $Object.Put('msds-allowedtoactonbehalfofotheridentity', $Existing_Rules.GetSecurityDescriptorBinaryForm())
                                        }
                                    }
                                } elseif ($Property.Name -eq 'certificates') {
                                    # Unwind the nested arrays if needed, so they can be checked properly.
                                    $UserCertificate_Values = @()
                                    $Special_Resolved_Properties_List[$Property.Name].GetEnumerator() | Where-Object { $_.Name -ne 'Clear' } | ForEach-Object { $UserCertificate_Values += $_.Value }

                                    foreach ($UserCertificate in $UserCertificate_Values) {
                                        if ($UserCertificate -isnot [System.Security.Cryptography.X509Certificates.X509Certificate]) {
                                            $Terminating_ErrorRecord_Parameters = @{
                                                'Exception'      = 'System.ArgumentException'
                                                'ID'             = 'DSS-{0}' -f $Function_Name
                                                'Category'       = 'InvalidType'
                                                'TargetObject'   = $Object
                                                'Message'        = 'All values in the argument collection "{0}" must be of Type: System.Security.Cryptography.X509Certificates.X509Certificate' -f $Property.Name
                                                'InnerException' = $_.Exception
                                            }
                                            $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                                            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                                        }
                                    }

                                    if ($Special_Resolved_Properties_List[$Property.Name]['Clear']) {
                                        Write-Verbose ('{0}|Special {1}: Clear: Clearing "usercertificate"' -f $Function_Name, $Property.Name)
                                        $Object.PutEx($ADS_PROPERTY_CLEAR, 'usercertificate', @())
                                    } elseif ($Special_Resolved_Properties_List[$Property.Name]['Replace']) {
                                        $UserCertificate_Replace = @()
                                        $Special_Resolved_Properties_List[$Property.Name]['Replace'] | ForEach-Object { $UserCertificate_Replace += , $_.GetRawCertData() }
                                        Write-Verbose ('{0}|Special {1}: Replace: Setting "usercertificate" with {2} objects' -f $Function_Name, $Property.Name, $UserCertificate_Replace.Count)
                                        $Object.PutEx($ADS_PROPERTY_UPDATE, 'usercertificate', $UserCertificate_Replace)
                                    } else {
                                        if ($Special_Resolved_Properties_List[$Property.Name]['Remove']) {
                                            $UserCertificate_Remove = @()
                                            $Special_Resolved_Properties_List[$Property.Name]['Remove'] | ForEach-Object { $UserCertificate_Remove += , $_.GetRawCertData() }
                                            Write-Verbose ('{0}|Special {1}: Remove: Removing {2} objects from "usercertificate"' -f $Function_Name, $Property.Name, $UserCertificate_Replace.Count)
                                            $Object.PutEx($ADS_PROPERTY_DELETE, 'usercertificate', $UserCertificate_Remove)
                                        }
                                        if ($Special_Resolved_Properties_List[$Property.Name]['Add']) {
                                            $UserCertificate_Add = @()
                                            $Special_Resolved_Properties_List[$Property.Name]['Add'] | ForEach-Object { $UserCertificate_Add += , $_.GetRawCertData() }
                                            Write-Verbose ('{0}|Special {1}: Add: Adding {2} objects to "usercertificate"' -f $Function_Name, $Property.Name, $UserCertificate_Add.Count)
                                            $Object.PutEx($ADS_PROPERTY_APPEND, 'usercertificate', $UserCertificate_Add)
                                        }
                                    }
                                }
                            }
                        }

                        Write-Verbose ('{0}|Applying properties on object' -f $Function_Name)
                        $Object.SetInfo()
                        Write-Verbose ('{0}|Properties applied successfully' -f $Function_Name)
                    }
                }

                'RemoveObject' {
                    $Whatif_Statement = 'Performing the operation "Remove" on target "{0}".' -f $($Object.'distinguishedname')
                    $Confirm_Statement = ('Are you sure you want to perform this action?', $Whatif_Statement) -join [Environment]::NewLine
                    if ($PSCmdlet.ShouldProcess($Whatif_Statement, $Confirm_Statement, 'Confirm')) {
                        Write-Verbose ('{0}|Found object, checking for ProtectFromAccidentalDeletion' -f $Function_Name)
                        $Check_Object_Parameters = @{
                            'DistinguishedName'   = $Object.'distinguishedname'
                            'Properties'          = 'protectedfromaccidentaldeletion'
                            'NoDefaultProperties' = $true
                        }
                        $Check_Object = Get-DSSObject @Common_Search_Parameters @Check_Object_Parameters
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
                        if ($Object.'objectclass' -contains 'Group') {
                            Write-Verbose ('{0}|Object is a group, getting parent OU first' -f $Function_Name)
                            $Group_Directory_Entry_Parent_OU = Get-DSSDirectoryEntry @Common_Search_Parameters -Path $Object.Parent
                            $Group_Directory_Entry_Parent_OU.Delete('Group', ('CN={0}' -f $Object.'cn'.Value))
                        } elseif ($Object.'objectclass' -contains 'OrganizationalUnit') {
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
            if ($_.Exception.ExtendedError -eq 1325) {
                # This exception is thrown when a disabled account has an unsuitable password, or no password.
                # LDAP response here: https://ldapwiki.com/wiki/ERROR_PASSWORD_RESTRICTION
                # Microsoft Error Code: https://docs.microsoft.com/en-gb/windows/win32/debug/system-error-codes--1300-1699-
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
            } elseif ($_.Exception.ExtendedError -eq 8373) {
                # This exception is thrown when you attempt to set a SPN value which is invalid.
                # Microsoft Error Code: https://docs.microsoft.com/en-gb/windows/win32/debug/system-error-codes--8200-8999-
                $Terminating_ErrorRecord_Parameters = @{
                    'Exception'      = 'System.DirectoryServices.DirectoryServicesCOMException'
                    'ID'             = 'DSS-{0}' -f $Function_Name
                    'Category'       = 'InvalidData'
                    'TargetObject'   = $Object
                    'Message'        = 'The name reference is invalid'
                    'InnerException' = $_.Exception
                }
                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
            } elseif ($_.Exception.ExtendedError -eq 8647) {
                # This exception is thrown when you attempt to set a SPN which is not unique forest-wide.
                # From: https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/spn-and-upn-uniqueness
                $Terminating_ErrorRecord_Parameters = @{
                    'Exception'      = 'System.DirectoryServices.DirectoryServicesCOMException'
                    'ID'             = 'DSS-{0}' -f $Function_Name
                    'Category'       = 'InvalidData'
                    'TargetObject'   = $Object
                    'Message'        = 'The operation failed because SPN value provided for addition/modification is not unique forest-wide'
                    'InnerException' = $_.Exception
                }
                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
            } elseif ($_.Exception.ExtendedError -eq 8648) {
                # This exception is thrown when you attempt to set a UPN which is not unique forest-wide.
                # From: https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/spn-and-upn-uniqueness
                $Terminating_ErrorRecord_Parameters = @{
                    'Exception'      = 'System.DirectoryServices.DirectoryServicesCOMException'
                    'ID'             = 'DSS-{0}' -f $Function_Name
                    'Category'       = 'InvalidData'
                    'TargetObject'   = $Object
                    'Message'        = 'The operation failed because UPN value provided for addition/modification is not unique forest-wide'
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
