function Find-DSSObject {
    <#
    .SYNOPSIS
        Finds an object in Active Directory.
    .DESCRIPTION
        Long description
    .EXAMPLE
        Example of how to use this script
    .EXAMPLE
        Another example of how to use this script
    .NOTES
        NOTE: Calling this function directly with "*" anywhere in the properties may not return all the correct UAC-related attributes, even if specifying the property in addition to the wildcard.
        Use the relevant Find-DSSUser/Find-DSSComputer/etc function instead.
    #>

    [CmdletBinding()]
    param(
        # The LDAP filter to use for the search.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $LDAPFilter,

        # The base OU to start the search from.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $SearchBase,

        # The scope to search. Must be one of: Base, OneLevel, Subtree.
        [Parameter(Mandatory = $false)]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope,

        # The properties of any results to return.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties = @('distinguishedname', 'objectclass', 'objectguid'),

        # The number of results per page that is returned from the server. This is primarily to save server memory and bandwidth and does not affect the total number of results returned.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('ResultPageSize')]
        [Int]
        $PageSize = 500,

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

    # A number of properties returned by the AD Cmdlets are calculated based on flags to one of the UserAccountControl LDAP properties.
    # The list of flags and their corresponding values are taken from here:
    # - https://support.microsoft.com/en-us/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro
    $UAC_Calculated_Properties = @{
        'useraccountcontrol'                 = @{
            'accountnotdelegated'               = '0x0100000'
            'allowreversiblepasswordencryption' = '0x0000080'
            'doesnotrequirepreauth'             = '0x0400000'
            'enabled'                           = '0x0000002'
            'homedirrequired'                   = '0x0000008'
            'mnslogonaccount'                   = '0x0020000'
            'passwordneverexpires'              = '0x0010000'
            'passwordnotrequired'               = '0x0000020'
            'smartcardlogonrequired'            = '0x0040000'
            'trustedfordelegation'              = '0x0080000'
            'trustedtoauthfordelegation'        = '0x1000000'
            'usedeskeyonly'                     = '0x0200000'
        }
        'msds-user-account-control-computed' = @{
            'lockedout'       = '0x0000010'
            'passwordexpired' = '0x0800000'
        }
    }

    # Get-ADUser also adds a number of other useful properties based on calculations of other properties. Like creating a datetime object from an integer property.
    $Useful_Calculated_Time_Properties = @{
        'lockouttime'     = 'accountlockouttime'
        'badpasswordtime' = 'lastbadpasswordattempt'
        'pwdlastset'      = 'passwordlastset'
    }
    $Useful_Calculated_Group_Properties = @{
        'primarygroupid' = 'primarygroup'
    }
    # These are all calculated from the 'ntsecuritydescriptor' property.
    $Useful_Calculated_Security_Properties = @(
        'cannotchangepassword'
        'protectedfromaccidentaldeletion'
    )

    # Get-ADDomain provides a number of "Container" properties which are calculated from the WellknownObjects or OtherWellknownObjects properties.
    # - Values taken from https://support.microsoft.com/en-gb/help/324949/redirecting-the-users-and-computers-containers-in-active-directory-dom
    $Containers_Calculated_Properties = @{
        'wellknownobjects'      = @{
            'computerscontainer'                 = 'B:32:AA312825768811D1ADED00C04FD8D5CD:'
            'deletedobjectscontainer'            = 'B:32:18E2EA80684F11D2B9AA00C04F79F805:'
            'domaincontrollerscontainer'         = 'B:32:A361B2FFFFD211D1AA4B00C04FD7D83A:'
            'foreignsecurityprincipalscontainer' = 'B:32:22B70C67D56E4EFB91E9300FCA3DC1AA:'
            'infrastructurecontainer'            = 'B:32:2FBAC1870ADE11D297C400C04FD8D5CD:'
            'lostandfoundcontainer'              = 'B:32:AB8153B7768811D1ADED00C04FD8D5CD:'
            'microsoftprogramdatacontainer'      = 'B:32:F4BE92A4C777485E878E9421D53087DB:'
            'programdatacontainer'               = 'B:32:09460C08AE1E4A4EA0F64AEE7DAA1E5A:'
            'quotascontainer'                    = 'B:32:6227F0AF1FC2410D8E3BB10615BB5B0F:'
            'systemscontainer'                   = 'B:32:AB1D30F3768811D1ADED00C04FD8D5CD:'
            'userscontainer'                     = 'B:32:A9D1CA15768811D1ADED00C04FD8D5CD:'
        }
        'otherwellknownobjects' = @{
            'keyscontainer'                   = 'B:32:683A24E2E8164BD3AF86AC3C2CF3F981:'
            'managedserviceaccountscontainer' = 'B:32:1EB93889E40C45DF9F0C64D23BBB6237:'
        }
    }

    # Get-ADDomain also adds some useful calculated properties.
    $Useful_Calculated_Domain_Properties = @{
        'gplink' = 'linkedgrouppolicyobjects'
    }

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    try {
        $Directory_Entry_Parameters = @{
            'Context' = $Context
        }
        if ($PSBoundParameters.ContainsKey('SearchBase')) {
            Write-Verbose ('{0}|Using SearchBase: {1}' -f $Function_Name, $SearchBase)
            $Directory_Entry_Parameters.SearchBase = $SearchBase
        }
        if ($PSBoundParameters.ContainsKey('Server')) {
            Write-Verbose ('{0}|Using Server: {1}' -f $Function_Name, $Server)
            $Directory_Entry_Parameters.Server = $Server
        }
        if ($PSBoundParameters.ContainsKey('Credential')) {
            Write-Verbose ('{0}|Using custom Credential' -f $Function_Name)
            $Directory_Entry_Parameters.Credential = $Credential
        }
        $Directory_Entry = Get-DSSDirectoryEntry @Directory_Entry_Parameters

        $Directory_Searcher_Arguments = @(
            $Directory_Entry
            $LDAPFilter
        )
        $Directory_Searcher = New-Object -TypeName 'System.DirectoryServices.DirectorySearcher' -ArgumentList $Directory_Searcher_Arguments

        if ($PSBoundParameters.ContainsKey('SearchScope')) {
            Write-Verbose ('{0}|Adding SearchScope: {1}' -f $Function_Name, $SearchScope)
            $Directory_Searcher.SearchScope = $SearchScope
        }

        Write-Verbose ('{0}|Setting PageSize to: {1}' -f $Function_Name, $PageSize)
        $Directory_Searcher.PageSize = $PageSize

        $Properties_To_Add = New-Object -TypeName 'System.Collections.Generic.List[String]'
        foreach ($Property in $Properties) {
            [void]$Properties_To_Add.Add($Property)

            # The relevant UserAccountControl calculated main property is added to the search properties list if any of the calculated sub-properties are requested.
            foreach ($UAC_Calculated_Property in $UAC_Calculated_Properties.GetEnumerator().Name) {
                if (($UAC_Calculated_Properties.$UAC_Calculated_Property.GetEnumerator().Name -contains $Property) -and ($Properties_To_Add -notcontains $UAC_Calculated_Property)) {
                    $Properties_To_Add.Add($UAC_Calculated_Property)
                }
            }

            # Add any of the "Useful Calculated Properties" if required.
            foreach ($Useful_Calculated_Time_Property in $Useful_Calculated_Time_Properties.GetEnumerator()) {
                if (($Useful_Calculated_Time_Property.Value -eq $Property) -and ($Properties_To_Add -notcontains $Useful_Calculated_Time_Property.Name)) {
                    $Properties_To_Add.Add($Useful_Calculated_Time_Property.Name)
                }
            }
            foreach ($Useful_Calculated_Group_Property in $Useful_Calculated_Group_Properties.GetEnumerator()) {
                if (($Useful_Calculated_Group_Property.Value -eq $Property) -and ($Properties_To_Add -notcontains $Useful_Calculated_Group_Property.Name)) {
                    $Properties_To_Add.Add($Useful_Calculated_Group_Property.Name)
                }
            }
            foreach ($Useful_Calculated_Security_Property in $Useful_Calculated_Security_Properties) {
                if (($Useful_Calculated_Security_Property -eq $Property) -and ($Properties_To_Add -notcontains 'ntsecuritydescriptor')) {
                    $Properties_To_Add.Add('ntsecuritydescriptor')
                }
            }

            # Add the relevant Containers calculated main property if a sub-property is requested.
            foreach ($Containers_Calculated_Property in $Containers_Calculated_Properties.GetEnumerator().Name) {
                if (($Containers_Calculated_Properties.$Containers_Calculated_Property.GetEnumerator().Name -contains $Property) -and ($Properties_To_Add -notcontains $Containers_Calculated_Property)) {
                    $Properties_To_Add.Add($Containers_Calculated_Property)
                }
            }
            foreach ($Useful_Calculated_Domain_Property in $Useful_Calculated_Domain_Properties.GetEnumerator()) {
                if (($Useful_Calculated_Domain_Property.Value -eq $Property) -and ($Properties_To_Add -notcontains $Useful_Calculated_Domain_Property.Name)) {
                    $Properties_To_Add.Add($Useful_Calculated_Domain_Property.Name)
                }
            }
        }
        Write-Verbose ('{0}|Adding Properties: {1}' -f $Function_Name, ($Properties_To_Add -join ' '))
        $Directory_Searcher.PropertiesToLoad.AddRange($Properties_To_Add)

        Write-Verbose ('{0}|Performing search...' -f $Function_Name)
        $Directory_Searcher_Results = $Directory_Searcher.FindAll()
        if ($Directory_Searcher_Results) {
            Write-Verbose ('{0}|Found {1} result(s)' -f $Function_Name, $Directory_Searcher_Results.Count)
            $Directory_Searcher_Result_To_Return = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'
            foreach ($Directory_Searcher_Result in $Directory_Searcher_Results) {
                $Result_Object = @{}
                $Directory_Searcher_Result.Properties.GetEnumerator() | ForEach-Object {
                    $Current_Searcher_Result_Property = $_.Name
                    $Current_Searcher_Result_Value = $($_.Value)
                    Write-Verbose ('{0}|Property={1} Value={2}' -f $Function_Name, $Current_Searcher_Result_Property, $Current_Searcher_Result_Value)

                    # Reformat certain properties:
                    switch ($Current_Searcher_Result_Property) {
                        # - NTSecurityDescriptor - replace with the System.DirectoryServices.ActiveDirectorySecurity object instead.
                        'ntsecuritydescriptor' {
                            Write-Verbose ('{0}|Reformatting to ActiveDirectorySecurity object: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                            $Current_Searcher_Result_Value = $Directory_Searcher_Result.GetDirectoryEntry().ObjectSecurity
                        }

                        # - GUID attributes - replace with System.Guid object
                        'objectguid' {
                            Write-Verbose ('{0}|Reformatting to GUID object: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                            $Current_Searcher_Result_Value = New-Object 'System.Guid' -ArgumentList @(, $Current_Searcher_Result_Value)
                        }

                        # - SID attributes - replace with SecurityIdentifier object
                        'objectsid' {
                            Write-Verbose ('{0}|Reformatting to SID object: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                            $Current_Searcher_Result_Value = New-Object 'System.Security.Principal.SecurityIdentifier' -ArgumentList @($Current_Searcher_Result_Value, 0)
                        }
                    }

                    # Add the calculated property if the property is found on one of the Calculated Property lists. Otherwise default to just outputting the property and value.
                    if ($UAC_Calculated_Properties.GetEnumerator().Name -contains $Current_Searcher_Result_Property) {
                        Write-Verbose ('{0}|UAC base property found: {1}={2}' -f $Function_Name, $Current_Searcher_Result_Property, $Current_Searcher_Result_Value)
                        # Only output the "UserAccountControl" property if it is explicitly requested.
                        if ($Properties -contains $Current_Searcher_Result_Property) {
                            Write-Verbose ('{0}|UAC: Base property specified directly: {0}' -f $Function_Name, $Current_Searcher_Result_Property)
                            $Result_Object[$Current_Searcher_Result_Property] = $Current_Searcher_Result_Value
                        }

                        # This does the following:
                        # - Looks through the "UserAccountControl" integer and extracts the flag(s) that this integer matches.
                        # - Loops through all the properties specified to the function and if there is a match, it will do this:
                        #   - 1. Set a default bool value of $true if the property is named "enabled" and $false for everything else.
                        #   - 2. If the flag is set, then it will flip the bool value to the opposite.
                        $UAC_Calculated_Properties.$Current_Searcher_Result_Property.GetEnumerator() | ForEach-Object {
                            $UAC_Calculated_Property_Name = $_.Name
                            $UAC_Calculated_Property_Flag = $_.Value
                            Write-Verbose ('{0}|UAC: Checking UAC calculated property: {1}={2}' -f $Function_Name, $UAC_Calculated_Property_Name, $UAC_Calculated_Property_Flag)
                            if ($Properties -contains $UAC_Calculated_Property_Name) {
                                Write-Verbose ('{0}|UAC: Processing property: {1}' -f $Function_Name, $UAC_Calculated_Property_Name)
                                if ($UAC_Calculated_Property_Name -eq 'enabled') {
                                    $UAC_Calculated_Property_Return = $true
                                } else {
                                    $UAC_Calculated_Property_Return = $false
                                }
                                if (($Current_Searcher_Result_Value -band $UAC_Calculated_Property_Flag) -eq $UAC_Calculated_Property_Flag) {
                                    $UAC_Calculated_Property_Return = -not $UAC_Calculated_Property_Return
                                }
                                Write-Verbose ('{0}|UAC: Return value for "{1}" is "{2}"' -f $Function_Name, $UAC_Calculated_Property_Name, $UAC_Calculated_Property_Return)
                                $Result_Object[$UAC_Calculated_Property_Name] = $UAC_Calculated_Property_Return
                            }
                        }

                    } elseif ($Useful_Calculated_Time_Properties.GetEnumerator().Name -contains $Current_Searcher_Result_Property) {
                        Write-Verbose ('{0}|Useful_Calculated_Time base property found: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                        $Useful_Calculated_Time_Property_Name = $Useful_Calculated_Time_Properties.$Current_Searcher_Result_Property
                        if ($Properties -contains $Current_Searcher_Result_Property) {
                            Write-Verbose ('{0}|Useful_Calculated_Time: Base property specified directly: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                            $Result_Object[$Current_Searcher_Result_Property] = $Current_Searcher_Result_Value
                        }
                        if ($Properties -contains $Useful_Calculated_Time_Property_Name) {
                            Write-Verbose ('{0}|Useful_Calculated_Time: Returning calculated property: {1}' -f $Function_Name, $Useful_Calculated_Time_Property_Name)
                            $Result_Object[$Useful_Calculated_Time_Property_Name] = [DateTime]::FromFileTime($Current_Searcher_Result_Value)
                        }

                    } elseif ($Useful_Calculated_Group_Properties.GetEnumerator().Name -contains $Current_Searcher_Result_Property) {
                        Write-Verbose ('{0}|Useful_Calculated_Group: Base property found: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                        $Useful_Calculated_Group_Property_Name = $Useful_Calculated_Group_Properties.$Current_Searcher_Result_Property

                        if ($Properties -contains $Current_Searcher_Result_Property) {
                            Write-Verbose ('{0}|Useful_Calculated_Group: Base property specified directly: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                            $Result_Object[$Current_Searcher_Result_Property] = $Current_Searcher_Result_Value
                        }
                        if ($Properties -contains $Useful_Calculated_Group_Property_Name) {
                            # Convert the PrimaryGroupID to a full ObjectSID property, by using the AccountDomainSid sub-property of the ObjectSID property of the user and appending the PrimaryGroupID.
                            $PrimaryGroup_SID = '{0}-{1}' -f $Result_Object['objectsid'].AccountDomainSid.Value, $Current_Searcher_Result_Value
                            $PrimaryGroup_Name = (Get-DSSGroup -ObjectSID $PrimaryGroup_SID).distinguishedname
                            Write-Verbose ('{0}|Useful_Calculated_Group: Returning calculated property: {1}' -f $Function_Name, $Useful_Calculated_Group_Property_Name)
                            $Result_Object[$Useful_Calculated_Group_Property_Name] = $PrimaryGroup_Name
                        }

                    } elseif ($Current_Searcher_Result_Property -eq 'ntsecuritydescriptor') {
                        Write-Verbose ('{0}|Useful_Calculated_Security base property found: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                        if ($Properties -contains $Current_Searcher_Result_Property) {
                            Write-Verbose ('{0}|Useful_Calculated_Security: Base property specified directly: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                            $Result_Object[$Current_Searcher_Result_Property] = $Current_Searcher_Result_Value
                        }
                        if ($Properties -contains 'cannotchangepassword') {
                            $Useful_Calculated_Security_Property_Name = 'cannotchangepassword'
                            Write-Verbose ('{0}|Useful_Calculated_Security: Returning calculated property: {1}' -f $Function_Name, $Useful_Calculated_Security_Property_Name)
                            # This requires 2 Deny permissions to be set: the "Everyone" group and "NT AUTHORITY\SELF" user. Only if both are set to Deny, will "cannotchangepassword" be true.
                            # Adapted from: https://social.technet.microsoft.com/Forums/scriptcenter/en-US/e947d590-d183-46b9-9a7a-4e785638c6fb/how-can-i-get-a-list-of-active-directory-user-accounts-where-the-user-cannot-change-the-password?forum=ITCG
                            $ChangePassword_GUID = 'ab721a53-1e2f-11d0-9819-00aa0040529b'
                            $ChangePassword_Identity_Everyone = 'Everyone'
                            $ChangePassword_Identity_Self = 'NT AUTHORITY\SELF'
                            $ChangePassword_Rules = $Current_Searcher_Result_Value.Access | Where-Object { $_.ObjectType -eq $ChangePassword_GUID }
                            $null = $ChangePassword_Identity_Everyone_Correct = $ChangePassword_Identity_Self_Correct
                            foreach ($ChangePassword_Rule in $ChangePassword_Rules) {
                                if (($ChangePassword_Rule.IdentityReference -eq $ChangePassword_Identity_Everyone) -and ($ChangePassword_Rule.AccessControlType -eq 'Deny')) {
                                    Write-Verbose ('{0}|Useful_Calculated_Security: CannotChangePassword: Found correct permission for "Everyone" group: {1}' -f $Function_Name, $ChangePassword_Identity_Everyone)
                                    $ChangePassword_Identity_Everyone_Correct = $true
                                }
                                if (($ChangePassword_Rule.IdentityReference -eq $ChangePassword_Identity_Self) -and ($ChangePassword_Rule.AccessControlType -eq 'Deny')) {
                                    Write-Verbose ('{0}|Useful_Calculated_Security: CannotChangePassword: Found correct permission for "Self" user: {1}' -f $Function_Name, $ChangePassword_Identity_Self)
                                    $ChangePassword_Identity_Self_Correct = $true
                                }
                            }
                            if ($ChangePassword_Identity_Everyone_Correct -and $ChangePassword_Identity_Self_Correct) {
                                Write-Verbose ('{0}|Useful_Calculated_Security: CannotChangePassword: Both permissions correct, returning $true' -f $Function_Name)
                                $Result_Object[$Useful_Calculated_Security_Property_Name] = $true
                            } else {
                                Write-Verbose ('{0}|Useful_Calculated_Security: CannotChangePassword: Both permissions not correct, returning $false' -f $Function_Name)
                                $Result_Object[$Useful_Calculated_Security_Property_Name] = $false
                            }
                        }
                        if ($Properties -contains 'protectedfromaccidentaldeletion') {
                            $Useful_Calculated_Security_Property_Name = 'protectedfromaccidentaldeletion'
                            Write-Verbose ('{0}|Useful_Calculated_Security: Returning calculated property: {1}' -f $Function_Name, $Useful_Calculated_Security_Property_Name)
                            $AccidentalDeletion_Rights = 'DeleteTree, Delete'
                            $AccidentalDeletion_Identity_Everyone = 'Everyone'
                            $AccidentalDeletion_Rule = $Current_Searcher_Result_Value.Access | Where-Object { ($_.ActiveDirectoryRights -eq $AccidentalDeletion_Rights) -and ($_.IdentityReference -eq $AccidentalDeletion_Identity_Everyone) }
                            if (($AccidentalDeletion_Rule.Count -eq 1) -and ($AccidentalDeletion_Rule.AccessControlType -eq 'Deny')) {
                                Write-Verbose ('{0}|Useful_Calculated_Security: AccidentalDeletion correct: Permission: {1} | Group: {2} | Count: {3}' -f $Function_Name, $AccidentalDeletion_Rule.AccessControlType, $AccidentalDeletion_Identity_Everyone, $AccidentalDeletion_Rule.Count)
                                $Result_Object[$Useful_Calculated_Security_Property_Name] = $true
                            } else {
                                Write-Verbose ('{0}|Useful_Calculated_Security: AccidentalDeletion incorrect: Permission: {1} | Group: {2} | Count: {3}' -f $Function_Name, $AccidentalDeletion_Rule.AccessControlType, $AccidentalDeletion_Identity_Everyone, $AccidentalDeletion_Rule.Count)
                                $Result_Object[$Useful_Calculated_Security_Property_Name] = $false
                            }
                        }

                    } elseif ($Containers_Calculated_Properties.GetEnumerator().Name -contains $Current_Searcher_Result_Property) {
                        Write-Verbose ('{0}|Containers base property found: {1}={2}' -f $Function_Name, $Current_Searcher_Result_Property, $Current_Searcher_Result_Value)
                        # Only output the Containers main property if it is explicitly requested.
                        if ($Properties -contains $Current_Searcher_Result_Property) {
                            Write-Verbose ('{0}|Containers: Base property specified directly: {0}' -f $Function_Name, $Current_Searcher_Result_Property)
                            $Result_Object[$Current_Searcher_Result_Property] = $Current_Searcher_Result_Value
                        }

                        $Containers_Calculated_Properties.$Current_Searcher_Result_Property.GetEnumerator() | ForEach-Object {
                            $Containers_Calculated_Property_Name = $_.Name
                            $Containers_Calculated_Property_GUID = $_.Value
                            Write-Verbose ('{0}|Containers: Checking Containers calculated property: {1}={2}' -f $Function_Name, $Containers_Calculated_Property_Name, $Containers_Calculated_Property_GUID)
                            if ($Properties -contains $Containers_Calculated_Property_Name) {
                                Write-Verbose ('{0}|Containers: Processing property: {1}' -f $Function_Name, $Containers_Calculated_Property_Name)
                                foreach ($Containers_Calculated_Property_Value in $Current_Searcher_Result_Value) {
                                    if ($Containers_Calculated_Property_Value -match $Containers_Calculated_Property_GUID) {
                                        $Containers_Calculated_Property_Return = $Containers_Calculated_Property_Value.Replace($Containers_Calculated_Property_GUID, '')
                                    }
                                }
                                $Result_Object[$Containers_Calculated_Property_Name] = $Containers_Calculated_Property_Return
                            }
                        }

                    } elseif ($Useful_Calculated_Domain_Properties.GetEnumerator().Name -contains $Current_Searcher_Result_Property) {
                        Write-Verbose ('{0}|Useful_Calculated_Domain base property found: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                        $Useful_Calculated_Domain_Property_Name = $Useful_Calculated_Domain_Properties.$Current_Searcher_Result_Property

                        if ($Properties -contains $Current_Searcher_Result_Property) {
                            Write-Verbose ('{0}|Useful_Calculated_Domain: Base property specified directly: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                            $Result_Object[$Current_Searcher_Result_Property] = $Current_Searcher_Result_Value
                        }
                        if ($Properties -contains $Useful_Calculated_Domain_Property_Name) {
                            Write-Verbose ('{0}|Useful_Calculated_Domain: Processing property: {1}' -f $Function_Name, $Useful_Calculated_Domain_Property_Name)
                            if ($Useful_Calculated_Domain_Property_Name -eq 'linkedgrouppolicyobjects') {
                                # Convert the "gplink" string property into an array of strings, selecting just the Group Policy DistinguishedName.
                                $Regex_GPLink = [System.Text.RegularExpressions.Regex]'\[LDAP://(.*?)\;\d\]'
                                $Result_Object[$Useful_Calculated_Domain_Property_Name] = $Regex_GPLink.Matches($Current_Searcher_Result_Value) | ForEach-Object { $_.Groups[1].Value }
                            }
                        }

                    } else {
                        $Result_Object[$Current_Searcher_Result_Property] = $Current_Searcher_Result_Value
                    }
                }

                # Sort the object alphabetically.
                $Directory_Searcher_Result_Object = ConvertTo-SortedPSObject -InputObject $Result_Object
                $Directory_Searcher_Result_To_Return.Add($Directory_Searcher_Result_Object)
            }
            # Return the search results object.
            $Directory_Searcher_Result_To_Return
        } else {
            Write-Verbose ('{0}|No results found!' -f $Function_Name)
        }
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
