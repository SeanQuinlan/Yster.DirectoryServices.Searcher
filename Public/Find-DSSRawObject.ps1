function Find-DSSRawObject {
    <#
    .SYNOPSIS
        Finds an object in Active Directory based on the specified LDAP filter provided.

        This is not meant to be used as an interactive function; it is used as a worker function by many of the other higher-level functions.
    .DESCRIPTION
        Long description
    .EXAMPLE
        Example of how to use this script
    .EXAMPLE
        Another example of how to use this script
    .NOTES
        NOTE: Calling this function directly with "*" anywhere in the properties may not return all the correct UAC-related attributes, even if specifying the property in addition to the wildcard.
        Use the relevant Find-DSSUser/Find-DSSComputer/etc function instead for more accurate results.

        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/get-adobject
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

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    # The order of properties returned from an LDAP search can be random, or at least they are not returned in the same order as they are requested.
    # Therefore certain properties need to be processed first when returned, as other properties may depend on them being already populated.
    $Returned_Properties_To_Process_First = @(
        'distinguishedname'
        'objectclass'
        'objectsid'
    )

    # The AD Cmdlets add a number of "user-friendly" property names which are simply aliases of the existing LDAP properties.
    # - LDAP properties first, AD alias(es) second.
    $Microsoft_Alias_Properties = @{
        'badpwdcount'                  = 'badlogoncount'
        'distinguishedname'            = 'computerobjectdn'
        'c'                            = 'country'
        'dnshostname'                  = 'hostname'
        'facsimiletelephonenumber'     = 'fax'
        'isdeleted'                    = 'deleted'
        'l'                            = 'city'
        'mail'                         = 'emailaddress'
        'maxpwdage'                    = 'maxpasswordage'
        'minpwdage'                    = 'minpasswordage'
        'minpwdlength'                 = 'minpasswordlength'
        'mobile'                       = 'mobilephone'
        'msds-assignedauthnpolicy'     = 'authenticationpolicy'
        'msds-assignedauthnpolicysilo' = 'authenticationpolicysilo'
        'msds-hostserviceaccount'      = 'serviceaccount'
        'msds-spnsuffixes'             = 'spnsuffixes'
        'o'                            = 'organization'
        'objectsid'                    = @('sid', 'domainsid')
        'office'                       = 'physicaldeliveryofficename'
        'postofficebox'                = 'pobox'
        'pwdhistorylength'             = 'passwordhistorycount'
        'serviceprincipalname'         = 'serviceprincipalnames'
        'sn'                           = 'surname'
        'st'                           = 'state'
        'street'                       = 'streetaddress'
        'subrefs'                      = 'subordinatereferences'
        'telephonenumber'              = 'officephone'
        'usercertificate'              = 'certificates'
        'userworkstations'             = 'logonworkstations'
        'whenchanged'                  = @('modified', 'modifytimestamp')
        'whencreated'                  = @('created', 'createtimestamp')
        'wwwhomepage'                  = 'homepage'
    }

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

    # The Get-AD* cmdlets also add a number of other useful properties based on calculations of other properties. Like creating a datetime object from an integer property.
    $Useful_Calculated_Time_Properties = @{
        'accountexpires'     = 'accountexpirationdate'
        'badpasswordtime'    = 'lastbadpasswordattempt'
        'lastlogontimestamp' = 'lastlogondate'
        'lockouttime'        = 'accountlockouttime'
        'pwdlastset'         = 'passwordlastset'
    }
    $Useful_Calculated_Group_Properties = @{
        'grouptype'      = 'groupscope'
        'primarygroupid' = 'primarygroup'
        'samaccounttype' = 'groupcategory'
    }
    # Properties which are returned as TimeSpan objects, based on an integer stored in Active Directory.
    $Useful_Calculated_TimeSpan_Properties = @{
        'msds-logontimesyncinterval' = 'lastlogonreplicationinterval'
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

    # Get-ADDomain and Get-ADOptionalFeature also adds some useful calculated properties.
    $Useful_Calculated_Domain_Properties = @{
        'gplink'                             = 'linkedgrouppolicyobjects'
        'msds-optionalfeatureflags'          = 'featurescope'
        'msds-optionalfeatureguid'           = 'featureguid'
        'msds-requireddomainbehaviorversion' = 'requireddomainmode'
        'msds-requiredforestbehaviorversion' = 'requiredforestmode'
    }

    # These are calculated from the 'msds-supportedencryptiontypes' property.
    $Useful_Calculated_Encryption_Properties = @(
        'compoundidentitysupported'
        'kerberosencryptiontype'
    )

    # These are calculated from the 'msds-allowedtoactonbehalfofotheridentity' property.
    $Useful_Calculated_Delegation_Properties = @(
        'principalsallowedtodelegatetoaccount'
    )

    # Some additional flags to the 'msds-supportedencryptiontypes' property which don't form part of the ADKerberosEncryptionTypes Enum.
    # - Taken from https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919
    $Additional_Encryption_Types = @{
        'FAST-Supported'                    = '0x10000'
        'Compound-Identity-Supported'       = '0x20000'
        'Claims-Supported'                  = '0x40000'
        'Resource-SID-Compression-Disabled' = '0x80000'
    }

    # These are calculated from the 'pwdproperties' property.
    # - Values taken from: https://docs.microsoft.com/en-us/windows/desktop/adschema/a-pwdproperties
    $Useful_Calculated_Password_Properties = @{
        'complexityenabled'           = '0x01'
        'reversibleencryptionenabled' = '0x10'
    }

    try {
        $Common_Search_Parameters = @{
            'Context' = $Context
        }
        if ($PSBoundParameters.ContainsKey('SearchBase')) {
            Write-Verbose ('{0}|Using SearchBase: {1}' -f $Function_Name, $SearchBase)
            $Common_Search_Parameters['SearchBase'] = $SearchBase
        }
        if ($PSBoundParameters.ContainsKey('Server')) {
            Write-Verbose ('{0}|Using Server: {1}' -f $Function_Name, $Server)
            $Common_Search_Parameters['Server'] = $Server
        }
        if ($PSBoundParameters.ContainsKey('Credential')) {
            Write-Verbose ('{0}|Using custom Credential' -f $Function_Name)
            $Common_Search_Parameters['Credential'] = $Credential
        }
        $Directory_Entry = Get-DSSDirectoryEntry @Common_Search_Parameters

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

            # Add the relevant LDAP property to the list if a Microsoft Alias Property is requested.
            foreach ($Microsoft_Alias_Property in $Microsoft_Alias_Properties.GetEnumerator()) {
                if (($Microsoft_Alias_Property.Value -contains $Property) -and ($Properties_To_Add -notcontains $Microsoft_Alias_Property.Name)) {
                    $Properties_To_Add.Add($Microsoft_Alias_Property.Name)
                }
            }

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
            foreach ($Useful_Calculated_TimeSpan_Property in $Useful_Calculated_TimeSpan_Properties.GetEnumerator()) {
                if (($Useful_Calculated_TimeSpan_Property.Value -eq $Property) -and ($Properties_To_Add -notcontains $Useful_Calculated_TimeSpan_Property.Name)) {
                    $Properties_To_Add.Add($Useful_Calculated_TimeSpan_Property.Name)
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

            # Add the 'msds-supportedencryptiontypes' property if any Encryption sub-properties are requested.
            foreach ($Useful_Calculated_Encryption_Property in $Useful_Calculated_Encryption_Properties) {
                if (($Useful_Calculated_Encryption_Property -eq $Property) -and ($Properties_To_Add -notcontains 'msds-supportedencryptiontypes')) {
                    $Properties_To_Add.Add('msds-supportedencryptiontypes')
                }
            }
            # Add the 'msds-allowedtoactonbehalfofotheridentity' property if any Delegation sub-properties are requested.
            foreach ($Useful_Calculated_Delegation_Property in $Useful_Calculated_Delegation_Properties) {
                if (($Useful_Calculated_Delegation_Property -eq $Property) -and ($Properties_To_Add -notcontains 'msds-allowedtoactonbehalfofotheridentity')) {
                    $Properties_To_Add.Add('msds-allowedtoactonbehalfofotheridentity')
                }
            }

            # Add the 'pwdproperties' property if any password-related properties are requested.
            foreach ($Useful_Calculated_Password_Property in $Useful_Calculated_Password_Properties.GetEnumerator()) {
                if (($Useful_Calculated_Password_Property.Name -eq $Property) -and ($Properties_To_Add -notcontains 'pwdproperties')) {
                    $Properties_To_Add.Add('pwdproperties')
                }
            }
        }
        Write-Verbose ('{0}|Adding Properties: {1}' -f $Function_Name, ($Properties_To_Add -join ' '))
        $Directory_Searcher.PropertiesToLoad.AddRange($Properties_To_Add)

        try {
            Write-Verbose ('{0}|Performing search...' -f $Function_Name)
            $Directory_Searcher_Results = $Directory_Searcher.FindAll()
        } catch {
            $Terminating_ErrorRecord_Parameters = @{
                'Exception'      = 'System.Security.Authentication.AuthenticationException'
                'ID'             = 'DSS-{0}' -f $Function_Name
                'Category'       = 'SecurityError'
                'TargetObject'   = $Directory_Searcher
                'Message'        = $_.Exception.InnerException.Message
                'InnerException' = $_.Exception
            }
            $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        }
        if ($Directory_Searcher_Results) {
            Write-Verbose ('{0}|Found {1} result(s)' -f $Function_Name, $Directory_Searcher_Results.Count)
            $Directory_Searcher_Result_To_Return = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'
            foreach ($Directory_Searcher_Result in $Directory_Searcher_Results) {
                Write-Verbose ('{0}|Reformatting result properties order' -f $Function_Name)
                $Reformatted_Directory_Searcher_Result = [Ordered]@{}
                $Directory_Searcher_Result.Properties.GetEnumerator() | ForEach-Object {
                    if ($Returned_Properties_To_Process_First -contains $_.Name) {
                        $Reformatted_Directory_Searcher_Result.Insert(0, $_.Name, $_.Value)
                    } else {
                        $Reformatted_Directory_Searcher_Result[$_.Name] = $_.Value
                    }
                }

                $Result_Object = @{}
                foreach ($Current_Searcher_Result in $Reformatted_Directory_Searcher_Result.GetEnumerator()) {
                    $Current_Searcher_Result_Property = $Current_Searcher_Result.Name
                    $Current_Searcher_Result_Value = $($Current_Searcher_Result.Value)
                    Write-Verbose ('{0}|Property={1} Value={2}' -f $Function_Name, $Current_Searcher_Result_Property, $Current_Searcher_Result_Value)

                    # Reformat certain properties:
                    switch -Regex ($Current_Searcher_Result_Property) {
                        # Durations stored as negative integers - convert to TimeSpans.
                        'lockoutduration|lockoutobservationwindow|maxpwdage|minpwdage' {
                            Write-Verbose ('{0}|Reformatting to TimeSpan object: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                            $Current_Searcher_Result_Value = New-TimeSpan -Seconds ([System.Math]::Abs($Current_Searcher_Result_Value / 10000000))
                        }

                        # Security objects stored as byte arrays - convert to System.DirectoryServices.ActiveDirectorySecurity object.
                        # - Taken from https://social.microsoft.com/Forums/en-US/4a2661f6-cfe1-45e8-958a-ff1b19d813a3/convert-default-security-descriptor-of-a-schema-class?forum=Offtopic
                        'msds-allowedtoactonbehalfofotheridentity|ntsecuritydescriptor' {
                            Write-Verbose ('{0}|Reformatting to ActiveDirectorySecurity object: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                            $Security_Object = New-Object -TypeName 'System.DirectoryServices.ActiveDirectorySecurity'
                            $Security_Object.SetSecurityDescriptorBinaryForm($Current_Searcher_Result_Value)
                            $Current_Searcher_Result_Value = $Security_Object
                        }

                        # GUID attributes - replace with System.Guid object.
                        'objectguid|featureguid|invocationid' {
                            Write-Verbose ('{0}|Reformatting to GUID object: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                            $Current_Searcher_Result_Value = New-Object -TypeName 'System.Guid' -ArgumentList @(, $Current_Searcher_Result_Value)
                        }

                        # SID attributes - replace with SecurityIdentifier object.
                        'objectsid|sidhistory' {
                            Write-Verbose ('{0}|Reformatting to SID object: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                            $Current_Searcher_Result_Value = New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList @($Current_Searcher_Result_Value, 0)
                        }
                    }

                    # Add the calculated property if the property is found on one of the Calculated Property lists. Otherwise default to just outputting the property and value.
                    if ($UAC_Calculated_Properties.GetEnumerator().Name -contains $Current_Searcher_Result_Property) {
                        Write-Verbose ('{0}|UAC: Base property found: {1}={2}' -f $Function_Name, $Current_Searcher_Result_Property, $Current_Searcher_Result_Value)
                        if ($Properties -contains $Current_Searcher_Result_Property) {
                            Write-Verbose ('{0}|UAC: Base property specified directly: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                            $Result_Object[$Current_Searcher_Result_Property] = $Current_Searcher_Result_Value
                        }

                        # This does the following:
                        # - Looks through the "UserAccountControl" integer and extracts the flag(s) that this integer matches.
                        # - Loops through all the properties specified to the function and if there is a match, it will do this:
                        #   - 1. Set a default bool value of $true if the property is named "enabled" and $false for everything else.
                        #   - 2. If the flag is set, then it will flip the bool value to the opposite.
                        foreach ($UAC_Calculated_Property in $UAC_Calculated_Properties.$Current_Searcher_Result_Property.GetEnumerator()) {
                            $UAC_Calculated_Property_Name = $UAC_Calculated_Property.Name
                            $UAC_Calculated_Property_Flag = $UAC_Calculated_Property.Value
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
                        Write-Verbose ('{0}|Useful_Calculated_Time: Base property found: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                        $Useful_Calculated_Time_Property_Name = $Useful_Calculated_Time_Properties.$Current_Searcher_Result_Property
                        if ($Properties -contains $Current_Searcher_Result_Property) {
                            Write-Verbose ('{0}|Useful_Calculated_Time: Base property specified directly: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                            $Result_Object[$Current_Searcher_Result_Property] = $Current_Searcher_Result_Value
                        }
                        if ($Properties -contains $Useful_Calculated_Time_Property_Name) {
                            if (($Current_Searcher_Result_Value -eq 0) -or ($Current_Searcher_Result_Value -gt [DateTime]::MaxValue.Ticks)) {
                                $Useful_Calculated_Time_Property_Value = $null
                            } else {
                                $Useful_Calculated_Time_Property_Value = [DateTime]::FromFileTime($Current_Searcher_Result_Value)
                            }
                            Write-Verbose ('{0}|Useful_Calculated_Time: Returning calculated property: {1}' -f $Function_Name, $Useful_Calculated_Time_Property_Name)
                            $Result_Object[$Useful_Calculated_Time_Property_Name] = $Useful_Calculated_Time_Property_Value
                        }

                    } elseif ($Useful_Calculated_Group_Properties.GetEnumerator().Name -contains $Current_Searcher_Result_Property) {
                        Write-Verbose ('{0}|Useful_Calculated_Group: Base property found: {1} - {2}' -f $Function_Name, $Current_Searcher_Result_Property,$Current_Searcher_Result_Value)
                        $Useful_Calculated_Group_Property_Name = $Useful_Calculated_Group_Properties.$Current_Searcher_Result_Property

                        if ($Properties -contains $Current_Searcher_Result_Property) {
                            Write-Verbose ('{0}|Useful_Calculated_Group: Base property specified directly: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                            $Result_Object[$Current_Searcher_Result_Property] = $Current_Searcher_Result_Value
                        }
                        if ($Properties -contains $Useful_Calculated_Group_Property_Name) {
                            Write-Verbose ('{0}|Useful_Calculated_Group: Calculating Property {1} from: {2}' -f $Function_Name, $Useful_Calculated_Group_Property_Name, $Current_Searcher_Result_Property)
                            if ($Useful_Calculated_Group_Property_Name -eq 'primarygroup') {
                                # Convert the PrimaryGroupID to a full ObjectSID property, by using the AccountDomainSid sub-property of the ObjectSID property of the user and appending the PrimaryGroupID.
                                $PrimaryGroup_SID = '{0}-{1}' -f $Result_Object['objectsid'].AccountDomainSid.Value, $Current_Searcher_Result_Value
                                $Group_Search_Parameters = $Common_Search_Parameters.PSObject.Copy()
                                $Group_Search_Parameters['ObjectSID'] = $PrimaryGroup_SID
                                $Useful_Calculated_Group_Property_Value = (Get-DSSGroup @Group_Search_Parameters).'distinguishedname'
                            } elseif ($Useful_Calculated_Group_Property_Name -eq 'groupscope') {
                                if (($Current_Searcher_Result_Value -bor 2) -eq $Current_Searcher_Result_Value) {
                                    $Useful_Calculated_Group_Property_Value = 'Global'
                                } elseif (($Current_Searcher_Result_Value -bor 4) -eq $Current_Searcher_Result_Value) {
                                    $Useful_Calculated_Group_Property_Value = 'Domain Local'
                                } elseif (($Current_Searcher_Result_Value -bor 8) -eq $Current_Searcher_Result_Value) {
                                    $Useful_Calculated_Group_Property_Value = 'Universal'
                                } else {
                                    $Useful_Calculated_Group_Property_Value = 'Unknown'
                                }
                            } elseif ($Useful_Calculated_Group_Property_Name -eq 'groupcategory') {
                                if (($Current_Searcher_Result_Value -eq 268435456) -or ($Current_Searcher_Result_Value -eq 536870912)) {
                                    $Useful_Calculated_Group_Property_Value = 'Security'
                                } elseif (($Current_Searcher_Result_Value -eq 268435457) -or ($Current_Searcher_Result_Value -eq 536870913)) {
                                    $Useful_Calculated_Group_Property_Value = 'Distribution'
                                } else {
                                    $Useful_Calculated_Group_Property_Value = 'Unknown'
                                }
                            }
                            Write-Verbose ('{0}|Useful_Calculated_Group: Returning calculated property: {1}' -f $Function_Name, $Useful_Calculated_Group_Property_Name)
                            $Result_Object[$Useful_Calculated_Group_Property_Name] = $Useful_Calculated_Group_Property_Value
                        }

                    } elseif ($Useful_Calculated_TimeSpan_Properties.GetEnumerator().Name -contains $Current_Searcher_Result_Property) {
                        Write-Verbose ('{0}|Useful_Calculated_TimeSpan: Base property found: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                        $Useful_Calculated_TimeSpan_Property_Name = $Useful_Calculated_TimeSpan_Properties.$Current_Searcher_Result_Property
                        if ($Properties -contains $Current_Searcher_Result_Property) {
                            Write-Verbose ('{0}|Useful_Calculated_TimeSpan: Base property specified directly: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                            $Result_Object[$Current_Searcher_Result_Property] = $Current_Searcher_Result_Value
                        }
                        if ($Properties -contains $Useful_Calculated_TimeSpan_Property_Name) {
                            $Useful_Calculated_TimeSpan_Property_Value = New-TimeSpan -Days $Current_Searcher_Result_Value
                            Write-Verbose ('{0}|Useful_Calculated_TimeSpan: Returning calculated property: {1}' -f $Function_Name, $Useful_Calculated_TimeSpan_Property_Name)
                            $Result_Object[$Useful_Calculated_TimeSpan_Property_Name] = $Useful_Calculated_TimeSpan_Property_Value
                        }

                    } elseif ($Current_Searcher_Result_Property -eq 'ntsecuritydescriptor') {
                        Write-Verbose ('{0}|Useful_Calculated_Security: Base property found: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
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
                            $ChangePassword_Identity_Everyone_SID = New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList ([System.Security.Principal.WellKnownSidType]::WorldSid, $null) # Everyone
                            $ChangePassword_Identity_Everyone = $ChangePassword_Identity_Everyone_SID.Translate([System.Security.Principal.NTAccount]).Value
                            $ChangePassword_Identity_Self_SID = New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList ([System.Security.Principal.WellKnownSidType]::SelfSid, $null) # NT AUTHORITY\SELF
                            $ChangePassword_Identity_Self = $ChangePassword_Identity_Self_SID.Translate([System.Security.Principal.NTAccount]).Value
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
                            if ($Result_Object['objectclass'] -contains 'organizationalunit') {
                                $AccidentalDeletion_Rights = 'DeleteChild, DeleteTree, Delete'
                            } else {
                                $AccidentalDeletion_Rights = 'DeleteTree, Delete'
                            }
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
                        Write-Verbose ('{0}|Containers: Base property found: {1}={2}' -f $Function_Name, $Current_Searcher_Result_Property, $Current_Searcher_Result_Value)
                        if ($Properties -contains $Current_Searcher_Result_Property) {
                            Write-Verbose ('{0}|Containers: Base property specified directly: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                            $Result_Object[$Current_Searcher_Result_Property] = $Current_Searcher_Result_Value
                        }

                        foreach ($Containers_Calculated_Property in $Containers_Calculated_Properties.$Current_Searcher_Result_Property.GetEnumerator()) {
                            $Containers_Calculated_Property_Name = $Containers_Calculated_Property.Name
                            $Containers_Calculated_Property_GUID = $Containers_Calculated_Property.Value
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
                        Write-Verbose ('{0}|Useful_Calculated_Domain: Base property found: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
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
                            } elseif ($Useful_Calculated_Domain_Property_Name -eq 'requireddomainmode') {
                                $Result_Object[$Useful_Calculated_Domain_Property_Name] = $DomainMode_Table[$Current_Searcher_Result_Value.ToString()]
                            } elseif ($Useful_Calculated_Domain_Property_Name -eq 'requiredforestmode') {
                                $Result_Object[$Useful_Calculated_Domain_Property_Name] = $ForestMode_Table[$Current_Searcher_Result_Value.ToString()]
                            } elseif ($Useful_Calculated_Domain_Property_Name -eq 'featurescope') {
                                $Result_Object[$Useful_Calculated_Domain_Property_Name] = $OptionalFeature_Scope_Table[$Current_Searcher_Result_Value.ToString()]
                            } elseif ($Useful_Calculated_Domain_Property_Name -eq 'featureguid') {
                                $Result_Object[$Useful_Calculated_Domain_Property_Name] = $Current_Searcher_Result_Value
                            }
                        }

                    } elseif ($Current_Searcher_Result_Property -eq 'msds-supportedencryptiontypes') {
                        Write-Verbose ('{0}|Useful_Calculated_Encryption: Base property found: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                        if ($Properties -contains $Current_Searcher_Result_Property) {
                            Write-Verbose ('{0}|Useful_Calculated_Encryption: Base property specified directly: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                            $Result_Object[$Current_Searcher_Result_Property] = $Current_Searcher_Result_Value
                        }
                        if ($Properties -contains 'kerberosencryptiontype') {
                            $Useful_Calculated_Encryption_Property_Name = 'kerberosencryptiontype'
                            Write-Verbose ('{0}|Useful_Calculated_Encryption: Processing property: {1}' -f $Function_Name, $Useful_Calculated_Encryption_Property_Name)
                            $Kerberos_Encryption_Types = [Enum]::Parse('ADKerberosEncryptionType', $Current_Searcher_Result_Value)
                            $Result_Object[$Useful_Calculated_Encryption_Property_Name] = $Kerberos_Encryption_Types
                        }
                        if ($Properties -contains 'compoundidentitysupported') {
                            $Useful_Calculated_Encryption_Property_Name = 'compoundidentitysupported'
                            $Useful_Calculated_Encryption_Property_Value = $Additional_Encryption_Types.'Compound-Identity-Supported'
                            Write-Verbose ('{0}|Useful_Calculated_Encryption: Processing property: {1}={2}' -f $Function_Name, $Useful_Calculated_Encryption_Property_Name, $Useful_Calculated_Encryption_Property_Value)
                            if (($Current_Searcher_Result_Value -band $Useful_Calculated_Encryption_Property_Value) -eq $Useful_Calculated_Encryption_Property_Value) {
                                Write-Verbose ('{0}|Useful_Calculated_Encryption: Returning true: {1}' -f $Function_Name, $Useful_Calculated_Encryption_Property_Name)
                                $Result_Object[$Useful_Calculated_Encryption_Property_Name] = $true
                            } else {
                                Write-Verbose ('{0}|Useful_Calculated_Encryption: Returning false: {1}' -f $Function_Name, $Useful_Calculated_Encryption_Property_Name)
                                $Result_Object[$Useful_Calculated_Encryption_Property_Name] = $false
                            }
                        }

                    } elseif ($Current_Searcher_Result_Property -eq 'msds-allowedtoactonbehalfofotheridentity') {
                        Write-Verbose ('{0}|Useful_Calculated_Delegation: Base property found: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                        if ($Properties -contains $Current_Searcher_Result_Property) {
                            Write-Verbose ('{0}|Useful_Calculated_Delegation: Base property specified directly: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                            $Result_Object[$Current_Searcher_Result_Property] = $Current_Searcher_Result_Value
                        }
                        if ($Properties -contains 'principalsallowedtodelegatetoaccount') {
                            $Useful_Calculated_Delegation_Property_Name = 'principalsallowedtodelegatetoaccount'
                            Write-Verbose ('{0}|Useful_Calculated_Delegation: Processing property: {1}' -f $Function_Name, $Useful_Calculated_Delegation_Property_Name)
                            $Delegation_Principals = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'
                            $Current_Searcher_Result_Value.Access | Where-Object { $_.'AccessControlType' -eq 'Allow' } | ForEach-Object {
                                # The computer object is stored as a System.Security.Principal.NTAccount object, with a default display of DOMAIN\COMPUTERNAME$.
                                # Convert this to a SID, which can then be looked up in Active Directory to find the DistinguishedName.
                                $Computer_Object = $_.'IdentityReference'
                                $Computer_SID = $Computer_Object.Translate([Security.Principal.SecurityIdentifier])
                                $Computer_Search_Parameters = $Common_Search_Parameters.PSObject.Copy()
                                $Computer_Search_Parameters['ObjectSID'] = $Computer_SID
                                $Computer_Search_Result = (Get-DSSComputer @Computer_Search_Parameters).distinguishedname
                                $Delegation_Principals.Add($Computer_Search_Result)
                            }
                            $Result_Object[$Useful_Calculated_Delegation_Property_Name] = $Delegation_Principals
                        }

                    } elseif ($Current_Searcher_Result_Property -eq 'pwdproperties') {
                        Write-Verbose ('{0}|Useful_Calculated_Password: Base property found: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                        if ($Properties -contains $Current_Searcher_Result_Property) {
                            Write-Verbose ('{0}|Useful_Calculated_Password: Base property specified directly: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                            $Result_Object[$Current_Searcher_Result_Property] = $Current_Searcher_Result_Value
                        }

                        foreach ($Useful_Calculated_Password_Property in $Useful_Calculated_Password_Properties.GetEnumerator()) {
                            if ($Properties -contains $Useful_Calculated_Password_Property.Name) {
                                Write-Verbose ('{0}|Useful_Calculated_Password: Processing property: {1}' -f $Function_Name, $Useful_Calculated_Password_Property.Name)
                                if (($Current_Searcher_Result_Value -band $Useful_Calculated_Password_Property.Value) -eq $Useful_Calculated_Password_Property.Value) {
                                    Write-Verbose ('{0}|Useful_Calculated_Password: Returning true: {1}' -f $Function_Name, $Useful_Calculated_Password_Property.Name)
                                    $Result_Object[$Useful_Calculated_Password_Property.Name] = $true
                                } else {
                                    Write-Verbose ('{0}|Useful_Calculated_Password: Returning false: {1}' -f $Function_Name, $Useful_Calculated_Password_Property.Name)
                                    $Result_Object[$Useful_Calculated_Password_Property.Name] = $false
                                }
                            }
                        }

                    } elseif ($Microsoft_Alias_Properties.GetEnumerator().Name -contains $Current_Searcher_Result_Property) {
                        Write-Verbose ('{0}|Microsoft_Alias: Base property found: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                        $Microsoft_Alias_Property_Name = $Microsoft_Alias_Properties.$Current_Searcher_Result_Property

                        if ($Properties -contains $Current_Searcher_Result_Property) {
                            Write-Verbose ('{0}|Microsoft_Alias: Base property specified directly: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                            $Result_Object[$Current_Searcher_Result_Property] = $Current_Searcher_Result_Value
                        }
                        $Microsoft_Alias_Property_Name | ForEach-Object {
                            if ($Properties -contains $_) {
                                Write-Verbose ('{0}|Microsoft_Alias: Adding alias property: {1}' -f $Function_Name, $_)
                                $Result_Object[$_] = $Current_Searcher_Result_Value
                            }
                        }

                    } else {
                        $Result_Object[$Current_Searcher_Result_Property] = $Current_Searcher_Result_Value
                    }
                }

                # Add the formatted object to the return array.
                $Directory_Searcher_Result_To_Return.Add($Result_Object)
            }

            $Directory_Searcher_Result_To_Return
        } else {
            Write-Verbose ('{0}|No results found!' -f $Function_Name)
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

# An Enum to determine KerberosEncryptionType.
# Taken from https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919
Add-Type -TypeDefinition @"
    [System.Flags]
    public enum ADKerberosEncryptionType {
        DES_CRC = 0x01,
        DES_MD5 = 0x02,
        RC4     = 0x04,
        AES128  = 0x08,
        AES256  = 0x10
    }
"@

# As of February 2019 there are only 2 OptionalFeatures available (Recycle Bin and Privileged Access Management) and both are Forest-wide in scope.
# Therefore the below table is a guess based on values taken from Enable-ADOptionalFeature - https://docs.microsoft.com/en-us/powershell/module/addsadministration/enable-adoptionalfeature
# Optional Features detailed here: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9ae2a9ad-970c-4938-a6bf-9c1fdc0b8b3e
$OptionalFeature_Scope_Table = @{
    '0' = 'Domain'
    '1' = 'ForestOrConfigurationSet'
}
