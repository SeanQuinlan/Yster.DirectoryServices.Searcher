function Find-DSSRawObject {
    <#
    .SYNOPSIS
        Finds an object in Active Directory based on the specified LDAP filter provided.
    .DESCRIPTION
        Returns the raw properties of an object based on the specified LDAP filter. Results are returned as an unsorted hashtable, meant for later formatting to an object using ConvertTo-SortedObject.

        This is not meant to be used as an interactive function; it is used as a worker function by most of the other higher-level functions.
    .EXAMPLE
        $Directory_Search_Parameters = @{
            'Context'    = 'Domain'
            'PageSize'   = 1000
            'SearchBase' = 'OU=Headquarters,DC=contoso,DC=com'
            'Properties' = @('distinguishedname','samaccountname')
            'LDAPFilter' = '(samaccountname=generic*)'
        }
        Find-DSSRawObject @Directory_Search_Parameters

        Returns two properties of the objects found with the above SAMAccountName.
    .NOTES
        NOTE: Calling this function directly with "*" anywhere in the properties may not return all the correct UAC-related attributes, even if specifying the property in addition to the wildcard.
        Use the relevant Find-DSSUser/Find-DSSComputer/etc function instead for more accurate results.

        References:
        https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.directorysearcher
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/get-adobject
        https://gallery.technet.microsoft.com/scriptcenter/List-Members-of-Large-Group-0eea0132
        https://evetsleep.github.io/activedirectory/2016/08/06/PagingMembers.html
    #>

    [CmdletBinding()]
    param(
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

        # Whether to return deleted objects in the search results.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $IncludeDeletedObjects,

        # The LDAP filter to use for the search.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $LDAPFilter,

        # The format of the output.
        [Parameter(Mandatory = $false)]
        [ValidateSet('DirectoryEntry', 'Hashtable')]
        [String]
        $OutputFormat = 'Hashtable',

        # The number of results per page that is returned from the server. This is primarily to save server memory and bandwidth and does not affect the total number of results returned.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('ResultPageSize')]
        [Int]
        $PageSize = 500,

        # The properties of any results to return.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties = @('distinguishedname', 'objectclass', 'objectguid'),

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

        # The server to connect to.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Server
    )

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    # The order of properties returned from an LDAP search can be random, or at least they are not returned in the same order as they are requested.
    # Therefore certain properties need to be processed first when returned, as other properties may depend on them being already populated.
    $Returned_Properties_To_Process_First = @(
        'adspath'
        'distinguishedname'
        'objectclass'
        'objectsid'
    )

    # A regular expression to determine if a property needs to be paged to return all values.
    $Paging_Regex = '\;range=(\d+)-(.*)'

    # Some returned properties are not directly from LDAP, but rather from a different method, eg. a DNS lookup done on the local machine.
    $Non_LDAP_Properties = @('enabledscopes', 'ipv4address', 'ipv6address', 'isdisableable')

    try {
        $Common_Parameters = @('Context', 'Server', 'Credential')
        $Common_Search_Parameters = @{}
        foreach ($Parameter in $Common_Parameters) {
            if ($PSBoundParameters.ContainsKey($Parameter)) {
                $Common_Search_Parameters[$Parameter] = Get-Variable -Name $Parameter -ValueOnly
            }
        }
        if ($PSBoundParameters.ContainsKey('SearchBase')) {
            $Directory_Entry = Get-DSSDirectoryEntry @Common_Search_Parameters -SearchBase $SearchBase
        } else {
            $Directory_Entry = Get-DSSDirectoryEntry @Common_Search_Parameters
        }

        $Directory_Searcher_Arguments = @(
            $Directory_Entry
            # LDAP filters seem to need TRUE and FALSE in boolean comparisons to be upper case, so simply convert any here.
            $LDAPFilter -replace '=true', '=TRUE' -replace '=false', '=FALSE'
        )
        $Directory_Searcher = New-Object -TypeName 'System.DirectoryServices.DirectorySearcher' -ArgumentList $Directory_Searcher_Arguments

        if ($PSBoundParameters.ContainsKey('SearchScope')) {
            Write-Verbose ('{0}|Adding SearchScope: {1}' -f $Function_Name, $SearchScope)
            $Directory_Searcher.SearchScope = $SearchScope
        }
        if ($PSBoundParameters.ContainsKey('IncludeDeletedObjects')) {
            Write-Verbose ('{0}|Including Deleted Objects (Tombstone): {1}' -f $Function_Name, $IncludeDeletedObjects)
            $Directory_Searcher.Tombstone = $IncludeDeletedObjects
        }

        Write-Verbose ('{0}|Setting PageSize to: {1}' -f $Function_Name, $PageSize)
        $Directory_Searcher.PageSize = $PageSize

        $Properties_To_Add = New-Object -TypeName 'System.Collections.Generic.List[String]'
        $Properties_To_Calculate_Later = New-Object -TypeName 'System.Collections.Generic.List[String]'
        foreach ($Property in $Properties) {
            if ($Non_LDAP_Properties -contains $Property) {
                $Properties_To_Calculate_Later.Add($Property)
            } else {
                $Properties_To_Add.Add($Property)

                foreach ($Combined_Calculated_Property in $Combined_Calculated_Properties.GetEnumerator()) {
                    if (($Combined_Calculated_Property.Value -contains $Property) -and ($Properties_To_Add -notcontains $Combined_Calculated_Property.Name)) {
                        Write-Verbose ('{0}|Adding calculated property: {1}' -f $Function_Name, $Combined_Calculated_Property.Name)
                        $Properties_To_Add.Add($Combined_Calculated_Property.Name)
                    }
                }

                foreach ($Current_Calculated_SubProperty in $Useful_Calculated_SubProperties.GetEnumerator().Name) {
                    if (($Useful_Calculated_SubProperties[$Current_Calculated_SubProperty].GetEnumerator().Name -contains $Property) -and ($Properties_To_Add -notcontains $Current_Calculated_SubProperty)) {
                        Write-Verbose ('{0}|Adding calculated subproperty: {1}' -f $Function_Name, $Current_Calculated_SubProperty)
                        $Properties_To_Add.Add($Current_Calculated_SubProperty)
                    }
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

        if ($Directory_Searcher_Results.Count) {
            Write-Verbose ('{0}|Found {1} result(s)' -f $Function_Name, $Directory_Searcher_Results.Count)
            Write-Verbose ('{0}|Returning {1}' -f $Function_Name, $OutputFormat)
            if ($OutputFormat -eq 'DirectoryEntry') {
                $Directory_Searcher_Results | ForEach-Object {
                    $_.GetDirectoryEntry()
                }
            } elseif ($OutputFormat -eq 'HashTable') {
                $Directory_Searcher_Result_To_Return = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'
                foreach ($Directory_Searcher_Result in $Directory_Searcher_Results) {
                    Write-Verbose ('{0}|Reformatting result properties order' -f $Function_Name)
                    $Reformatted_Directory_Searcher_Result = [Ordered]@{}
                    # In order to keep the logic in the main part of this script, I need to process any paged properties before their regular counterparts, otherwise they get overwritten by null values.
                    $Directory_Searcher_Result.Properties.GetEnumerator() | ForEach-Object {
                        if ($Returned_Properties_To_Process_First -contains $_.Name) {
                            $Reformatted_Directory_Searcher_Result[$_.Name] = $_.Value
                        }
                    }
                    $Directory_Searcher_Result.Properties.GetEnumerator() | ForEach-Object {
                        if ($_.Name -match $Paging_Regex) {
                            $Reformatted_Directory_Searcher_Result[$_.Name] = $_.Value
                        }
                    }
                    $Directory_Searcher_Result.Properties.GetEnumerator() | ForEach-Object {
                        if (-not $Reformatted_Directory_Searcher_Result[$_.Name]) {
                            $Reformatted_Directory_Searcher_Result[$_.Name] = $_.Value
                        }
                    }

                    $Result_Object = @{}
                    foreach ($Current_Searcher_Result in $Reformatted_Directory_Searcher_Result.GetEnumerator().Name) {
                        $Current_Searcher_Result_Property = $Current_Searcher_Result
                        $Current_Searcher_Result_Value = $($Reformatted_Directory_Searcher_Result[$Current_Searcher_Result])
                        Write-Verbose ('{0}|Results: Property={1} Value={2}' -f $Function_Name, $Current_Searcher_Result_Property, $Current_Searcher_Result_Value)

                        ######################################
                        # STEP 1: Reformat certain properties.
                        ######################################
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

                        # Reformat any DateTime objects from UTC to local time (which is what the ActiveDirectory module does).
                        if ($Current_Searcher_Result_Value -is [DateTime]) {
                            $Current_Searcher_Result_Value = [System.TimeZoneInfo]::ConvertTimeFromUtc($Current_Searcher_Result_Value, [System.TimeZoneInfo]::Local)
                        }

                        # Page additional results if a property requires it.
                        if ($Current_Searcher_Result_Property -match $Paging_Regex) {
                            $Current_Searcher_Result_Base_Property = $Current_Searcher_Result_Property -replace $Paging_Regex, ''
                            Write-Verbose ('{0}|Paging: Found property requiring paging: {1}' -f $Function_Name, $Current_Searcher_Result_Base_Property)
                            $Paging_Results = New-Object -TypeName 'System.Collections.Generic.List[Object]'
                            $Paging_Results.AddRange($Current_Searcher_Result_Value)
                            $Paging_Total = $Current_Searcher_Result_Value.Count
                            $Paging_Start = $Matches[1]
                            $Paging_End = $Matches[2]

                            $Paging_Directory_Entry_Parameters = $Common_Search_Parameters.PSBase.Clone()
                            $Paging_Directory_Entry_Parameters['SearchBase'] = $Result_Object['distinguishedname']
                            $Paging_Directory_Entry = Get-DSSDirectoryEntry @Paging_Directory_Entry_Parameters
                            $Paging_Directory_Searcher = New-Object -TypeName 'System.DirectoryServices.DirectorySearcher' -ArgumentList @($Paging_Directory_Entry)

                            do {
                                $Paging_Start = [int]$Paging_Start + $Paging_Total
                                $Paging_End = [int]$Paging_End + $Paging_Total
                                $Paging_Property = '{0};range={1}-{2}' -f $Current_Searcher_Result_Base_Property, $Paging_Start, $Paging_End
                                $Paging_Directory_Searcher.PropertiesToLoad.Clear()
                                [void]$Paging_Directory_Searcher.PropertiesToLoad.Add($Paging_Property)
                                Write-Verbose ('{0}|Paging: Searching for this range: {1}' -f $Function_Name, $Paging_Property)

                                try {
                                    Write-Verbose ('{0}|Paging: Performing search...' -f $Function_Name)
                                    $Paging_Directory_Searcher_Result = $Paging_Directory_Searcher.FindOne()
                                } catch {
                                    $Terminating_ErrorRecord_Parameters = @{
                                        'Exception'      = 'System.Security.Authentication.AuthenticationException'
                                        'ID'             = 'DSS-{0}' -f $Function_Name
                                        'Category'       = 'SecurityError'
                                        'TargetObject'   = $Paging_Directory_Searcher
                                        'Message'        = $_.Exception.InnerException.Message
                                        'InnerException' = $_.Exception
                                    }
                                    $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                                    $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                                }
                                if ($Paging_Directory_Searcher_Result) {
                                    $Paging_Result = $Paging_Directory_Searcher_Result.Properties.GetEnumerator() | Where-Object { $_.'Name' -match $Current_Searcher_Result_Base_Property }
                                    $Paging_Result_Name = $Paging_Result.Name
                                    $Paging_Result_Value = $($Paging_Result.Value)
                                    Write-Verbose ('{0}|Paging: Found {1} results' -f $Function_Name, $Paging_Result_Value.Count)

                                    $Paging_Results.AddRange($Paging_Result_Value)
                                    $null = $Paging_Result_Name -match $Paging_Regex
                                    $Paging_Start = $Matches[1]
                                    $Paging_End = $Matches[2]
                                } else {
                                    Write-Verbose ('{0}|Paging: No result returned from paging search!')
                                    $Terminating_ErrorRecord_Parameters = @{
                                        'Exception'    = 'ActiveDirectory.InvalidResult'
                                        'ID'           = 'DSS-{0}' -f $Function_Name
                                        'Category'     = 'InvalidResult'
                                        'TargetObject' = $Paging_Directory_Searcher
                                        'Message'      = 'Incomplete paging result set returned'
                                    }
                                    $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                                    $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                                }

                            } until ($Paging_End -match '\*')

                            Write-Verbose ('{0}|Paging: Completed paging, adding regular property: {1} with {2} entries' -f $Function_Name, $Current_Searcher_Result_Base_Property, $Paging_Results.Count)
                            $Reformatted_Directory_Searcher_Result[$Current_Searcher_Result_Base_Property] = $Paging_Results
                        }

                        if ($Useful_Calculated_Properties.GetEnumerator().Name -contains $Current_Searcher_Result_Property) {
                            #######################################################################################################
                            # STEP 2: Add the calculated property if the property is found on one of the Calculated Property lists.
                            #######################################################################################################
                            Write-Verbose ('{0}|Useful_Properties: Base property found: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                            $Useful_Calculated_Property_Names = $Useful_Calculated_Properties[$Current_Searcher_Result_Property]

                            if ($Properties -contains $Current_Searcher_Result_Property) {
                                Write-Verbose ('{0}|Useful_Properties: Base property specified directly: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                                $Result_Object[$Current_Searcher_Result_Property] = $Current_Searcher_Result_Value
                            }
                            foreach ($Useful_Calculated_Property_Name in $Useful_Calculated_Property_Names) {
                                if ($Properties -contains $Useful_Calculated_Property_Name) {
                                    Write-Verbose ('{0}|Useful_Properties: Processing calculated property: {1}' -f $Function_Name, $Useful_Calculated_Property_Name)

                                    switch -Regex ($Useful_Calculated_Property_Name) {
                                        # Delegation properties
                                        'principalsallowedtodelegatetoaccount' {
                                            $Delegation_Principals = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'
                                            $Current_Searcher_Result_Value.Access | Where-Object { $_.'AccessControlType' -eq 'Allow' } | ForEach-Object {
                                                # The computer object is stored as a System.Security.Principal.NTAccount object, with a default display of DOMAIN\COMPUTERNAME$.
                                                # Convert this to a SID, which can then be looked up in Active Directory to find the DistinguishedName.
                                                $Computer_Object = $_.'IdentityReference'
                                                $Computer_SID = $Computer_Object.Translate([Security.Principal.SecurityIdentifier])
                                                $Computer_Search_Parameters = @{}
                                                $Computer_Search_Parameters['ObjectSID'] = $Computer_SID
                                                $Computer_Search_Result = (Get-DSSComputer @Common_Search_Parameters @Computer_Search_Parameters).'distinguishedname'
                                                $Delegation_Principals.Add($Computer_Search_Result)
                                            }
                                            $Useful_Calculated_Property_Value = $Delegation_Principals
                                        }

                                        # Domain properties
                                        'featurescope' {
                                            $Useful_Calculated_Property_Value = $OptionalFeature_Scope_Table[$Current_Searcher_Result_Value.ToString()]
                                        }
                                        'linkedgrouppolicyobjects' {
                                            # Convert the "gplink" string property into an array of strings, selecting just the Group Policy DistinguishedName.
                                            $Regex_GPLink = [System.Text.RegularExpressions.Regex]'\[LDAP://(.*?)\;\d\]'
                                            $Useful_Calculated_Property_Value = $Regex_GPLink.Matches($Current_Searcher_Result_Value) | ForEach-Object { $_.Groups[1].Value }
                                        }
                                        'requireddomainmode' {
                                            $Useful_Calculated_Property_Value = $DomainMode_Table[$Current_Searcher_Result_Value.ToString()]
                                        }
                                        'requiredforestmode' {
                                            $Useful_Calculated_Property_Value = $ForestMode_Table[$Current_Searcher_Result_Value.ToString()]
                                        }

                                        # Encryption properties
                                        'compoundidentitysupported' {
                                            $Compound_Identity_Value = $Additional_Encryption_Types.'Compound-Identity-Supported'
                                            if (($Current_Searcher_Result_Value -band $Compound_Identity_Value) -eq $Compound_Identity_Value) {
                                                $Useful_Calculated_Property_Value = $true
                                            } else {
                                                $Useful_Calculated_Property_Value = $false
                                            }
                                        }
                                        'kerberosencryptiontype' {
                                            $Useful_Calculated_Property_Value = ([Enum]::Parse('ADKerberosEncryptionType', $Current_Searcher_Result_Value, $true) -split ',').Trim()
                                        }

                                        # Group properties
                                        'groupcategory' {
                                            if (($Current_Searcher_Result_Value -bor $ADGroupTypes['Security']) -eq $Current_Searcher_Result_Value) {
                                                $Useful_Calculated_Property_Value = 'Security'
                                            } else {
                                                $Useful_Calculated_Property_Value = 'Distribution'
                                            }
                                        }
                                        'groupscope' {
                                            if (($Current_Searcher_Result_Value -bor $ADGroupTypes['Global']) -eq $Current_Searcher_Result_Value) {
                                                $Useful_Calculated_Property_Value = 'Global'
                                            } elseif (($Current_Searcher_Result_Value -bor $ADGroupTypes['DomainLocal']) -eq $Current_Searcher_Result_Value) {
                                                $Useful_Calculated_Property_Value = 'Domain Local'
                                            } elseif (($Current_Searcher_Result_Value -bor $ADGroupTypes['Universal']) -eq $Current_Searcher_Result_Value) {
                                                $Useful_Calculated_Property_Value = 'Universal'
                                            } else {
                                                $Useful_Calculated_Property_Value = 'Unknown'
                                            }
                                        }
                                        'isreadonly' {
                                            # 521 is the group ID for "Read-only Domain Controllers"
                                            if ($Result_Object['primarygroupid'] -eq 521) {
                                                $Useful_Calculated_Property_Value = $true
                                            } else {
                                                $Useful_Calculated_Property_Value = $false
                                            }
                                        }
                                        'primarygroup' {
                                            # Convert the PrimaryGroupID to a full ObjectSID property, by using the AccountDomainSid sub-property of the ObjectSID property of the user and appending the PrimaryGroupID.
                                            $PrimaryGroup_SID = '{0}-{1}' -f $Result_Object['objectsid'].AccountDomainSid.Value, $Current_Searcher_Result_Value
                                            $Group_Search_Parameters = @{}
                                            $Group_Search_Parameters['ObjectSID'] = $PrimaryGroup_SID
                                            $Useful_Calculated_Property_Value = (Get-DSSGroup @Common_Search_Parameters @Group_Search_Parameters).'distinguishedname'
                                        }

                                        # Security properties
                                        'cannotchangepassword' {
                                            # This requires 2 Deny permissions to be set: the "Everyone" group and "NT AUTHORITY\SELF" user. Only if both are set to Deny, will "cannotchangepassword" be true.
                                            # Adapted from: https://social.technet.microsoft.com/Forums/scriptcenter/en-US/e947d590-d183-46b9-9a7a-4e785638c6fb/how-can-i-get-a-list-of-active-directory-user-accounts-where-the-user-cannot-change-the-password?forum=ITCG
                                            $ChangePassword_Rules = $Current_Searcher_Result_Value.Access | Where-Object { $_.ObjectType -eq $ChangePassword_GUID }
                                            $null = $ChangePassword_Identity_Everyone_Correct = $ChangePassword_Identity_Self_Correct
                                            foreach ($ChangePassword_Rule in $ChangePassword_Rules) {
                                                if (($ChangePassword_Rule.IdentityReference -eq $Localised_Identity_Everyone_Object.Value) -and ($ChangePassword_Rule.AccessControlType -eq 'Deny')) {
                                                    Write-Verbose ('{0}|Security: CannotChangePassword: Found correct permission for "Everyone" group: {1}' -f $Function_Name, $Localised_Identity_Everyone_Object.Value)
                                                    $ChangePassword_Identity_Everyone_Correct = $true
                                                }
                                                if (($ChangePassword_Rule.IdentityReference -eq $Localised_Identity_Self_Object.Value) -and ($ChangePassword_Rule.AccessControlType -eq 'Deny')) {
                                                    Write-Verbose ('{0}|Security: CannotChangePassword: Found correct permission for "Self" user: {1}' -f $Function_Name, $Localised_Identity_Self_Object.Value)
                                                    $ChangePassword_Identity_Self_Correct = $true
                                                }
                                            }
                                            if ($ChangePassword_Identity_Everyone_Correct -and $ChangePassword_Identity_Self_Correct) {
                                                Write-Verbose ('{0}|Security: CannotChangePassword: Both permissions correct, returning $true' -f $Function_Name)
                                                $Useful_Calculated_Property_Value = $true
                                            } else {
                                                Write-Verbose ('{0}|Security: CannotChangePassword: Both permissions not correct, returning $false' -f $Function_Name)
                                                $Useful_Calculated_Property_Value = $false
                                            }
                                        }
                                        'protectedfromaccidentaldeletion' {
                                            $AccidentalDeletion_Rule = $Current_Searcher_Result_Value.Access | Where-Object { ($_.ActiveDirectoryRights -match $AccidentalDeletion_Rights) -and ($_.IdentityReference -eq $Localised_Identity_Everyone_Object.Value) }
                                            if (($AccidentalDeletion_Rule.Count -eq 1) -and ($AccidentalDeletion_Rule.AccessControlType -eq 'Deny')) {
                                                Write-Verbose ('{0}|Security: AccidentalDeletion correct: Permission: {1} | Group: {2} | Count: {3}' -f $Function_Name, $AccidentalDeletion_Rule.AccessControlType, $Localised_Identity_Everyone_Object.Value, $AccidentalDeletion_Rule.Count)
                                                $Useful_Calculated_Property_Value = $true
                                            } else {
                                                Write-Verbose ('{0}|Security: AccidentalDeletion incorrect: Permission: {1} | Group: {2} | Count: {3}' -f $Function_Name, $AccidentalDeletion_Rule.AccessControlType, $Localised_Identity_Everyone_Object.Value, $AccidentalDeletion_Rule.Count)
                                                $Useful_Calculated_Property_Value = $false
                                            }
                                        }

                                        # Time properties
                                        'accountexpirationdate|lastbadpasswordattempt|lastlogondate|accountlockouttime|passwordlastset' {
                                            if (($Current_Searcher_Result_Value -eq 0) -or ($Current_Searcher_Result_Value -gt [DateTime]::MaxValue.Ticks)) {
                                                $Useful_Calculated_Property_Value = $null
                                            } else {
                                                $Useful_Calculated_Property_Value = [DateTime]::FromFileTime($Current_Searcher_Result_Value)
                                            }
                                        }

                                        # TimeSpan properties
                                        'lastlogonreplicationinterval' {
                                            $Useful_Calculated_Property_Value = New-TimeSpan -Days $Current_Searcher_Result_Value
                                        }

                                        # Custom Properties
                                        'domainname' {
                                            # This is simply everything before the first "/" in the canonicalname.
                                            $Useful_Calculated_Property_Value = $Current_Searcher_Result_Value.Split('/')[0]
                                        }
                                    }

                                    Write-Verbose ('{0}|Useful_Properties: Returning calculated property: {1} = {2}' -f $Function_Name, $Useful_Calculated_Property_Name, $Useful_Calculated_Property_Value)
                                    $Result_Object[$Useful_Calculated_Property_Name] = $Useful_Calculated_Property_Value
                                }
                            }

                        } elseif ($Useful_Calculated_SubProperties.GetEnumerator().Name -contains $Current_Searcher_Result_Property) {
                            ##########################################################################################################
                            # STEP 3: Add the calculated property if the property is found on one of the Calculated SubProperty lists.
                            ##########################################################################################################
                            Write-Verbose ('{0}|Useful_SubProperties: Base property found: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                            if ($Properties -contains $Current_Searcher_Result_Property) {
                                Write-Verbose ('{0}|Useful_SubProperties: Base property specified directly: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                                $Result_Object[$Current_Searcher_Result_Property] = $Current_Searcher_Result_Value
                            }

                            foreach ($Useful_Calculated_SubProperty in $Useful_Calculated_SubProperties[$Current_Searcher_Result_Property].GetEnumerator()) {
                                $Useful_Calculated_SubProperty_Name = $Useful_Calculated_SubProperty.Name
                                $Useful_Calculated_SubProperty_Flag = $Useful_Calculated_SubProperty.Value

                                if ($Properties -contains $Useful_Calculated_SubProperty_Name) {
                                    Write-Verbose ('{0}|Useful_SubProperties: Processing calculated subproperty: {1} = {2}' -f $Function_Name, $Useful_Calculated_SubProperty_Name, $Useful_Calculated_SubProperty_Flag)

                                    switch -Regex ($Current_Searcher_Result_Property) {
                                        # For any value calculated from the "UserAccountControl" integer, the following is done:
                                        #   - 1. Set a default bool value of $true if the property is named "enabled" and $false for everything else.
                                        #   - 2. If the flag is set, then it will flip the bool value to the opposite.
                                        'useraccountcontrol|msds-user-account-control-computed' {
                                            if ($Useful_Calculated_SubProperty_Name -eq 'enabled') {
                                                $UAC_Calculated_SubProperty_Return = $true
                                            } else {
                                                $UAC_Calculated_SubProperty_Return = $false
                                            }
                                            if (($Current_Searcher_Result_Value -band $Useful_Calculated_SubProperty_Flag) -eq $Useful_Calculated_SubProperty_Flag) {
                                                $UAC_Calculated_SubProperty_Return = -not $UAC_Calculated_SubProperty_Return
                                            }
                                            $Useful_Calculated_SubProperty_Value = $UAC_Calculated_SubProperty_Return
                                        }

                                        # "Container" properties
                                        'wellknownobjects|otherwellknownobjects' {
                                            foreach ($Containers_Calculated_Property_Value in $Current_Searcher_Result_Value) {
                                                if ($Containers_Calculated_Property_Value -match $Useful_Calculated_SubProperty_Flag) {
                                                    $Useful_Calculated_SubProperty_Value = $Containers_Calculated_Property_Value.Replace($Useful_Calculated_SubProperty_Flag, '')
                                                }
                                            }
                                        }

                                        # Password properties
                                        'pwdproperties' {
                                            if (($Current_Searcher_Result_Value -band $Useful_Calculated_SubProperty_Flag) -eq $Useful_Calculated_SubProperty_Flag) {
                                                $Useful_Calculated_SubProperty_Value = $true
                                            } else {
                                                $Useful_Calculated_SubProperty_Value = $false
                                            }
                                        }
                                    }

                                    Write-Verbose ('{0}|Useful_SubProperties: Returning calculated subproperty: {1} = {2}' -f $Function_Name, $Useful_Calculated_SubProperty_Name, $Useful_Calculated_SubProperty_Value)
                                    $Result_Object[$Useful_Calculated_SubProperty_Name] = $Useful_Calculated_SubProperty_Value
                                }
                            }

                        } elseif ($Microsoft_Alias_Properties.GetEnumerator().Name -contains $Current_Searcher_Result_Property) {
                            ####################################
                            # STEP 4: Add any Microsoft Aliases.
                            ####################################
                            Write-Verbose ('{0}|Microsoft_Alias: Base property found: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                            $Microsoft_Alias_Property_Names = $Microsoft_Alias_Properties[$Current_Searcher_Result_Property]

                            if ($Properties -contains $Current_Searcher_Result_Property) {
                                Write-Verbose ('{0}|Microsoft_Alias: Base property specified directly: {1}' -f $Function_Name, $Current_Searcher_Result_Property)
                                $Result_Object[$Current_Searcher_Result_Property] = $Current_Searcher_Result_Value
                            }
                            $Microsoft_Alias_Property_Names | ForEach-Object {
                                if ($Properties -contains $_) {
                                    Write-Verbose ('{0}|Microsoft_Alias: Adding alias property: {1}' -f $Function_Name, $_)
                                    $Result_Object[$_] = $Current_Searcher_Result_Value
                                }
                            }

                        } elseif ($Current_Searcher_Result_Property -notmatch $Paging_Regex) {
                            ###################################################################################
                            # STEP 5: If no matches, simply add the property as it is returned from the server.
                            ###################################################################################
                            Write-Verbose ('{0}|Default: Adding property: {1} - {2}' -f $Function_Name, $Current_Searcher_Result_Property, $Current_Searcher_Result_Value)
                            $Result_Object[$Current_Searcher_Result_Property] = $Current_Searcher_Result_Value
                        }
                    }

                    if ($Properties_To_Calculate_Later.Count) {
                        foreach ($Property in $Properties_To_Calculate_Later) {
                            switch -Regex ($Property) {
                                'ipv[4|6]address' {
                                    # Useful post here: https://www.myotherpcisacloud.com/post/IPv4Address-Attribute-In-Get-ADComputer
                                    # Try and get the IP address(es) from DNS or just return null if any error.
                                    try {
                                        $Host_IP_Addresses = [System.Net.Dns]::GetHostEntry($Result_Object['dnshostname']).AddressList
                                    } catch {
                                        $Host_IP_Addresses = $null
                                    }
                                    if ($Property -eq 'ipv4address') {
                                        $Calculate_Later_Value = ($Host_IP_Addresses | Where-Object { $_.AddressFamily -eq 'InterNetwork' }).'IPAddressToString'
                                    } elseif ($Property -eq 'ipv6address') {
                                        $Calculate_Later_Value = ($Host_IP_Addresses | Where-Object { ($_.AddressFamily -eq 'InterNetworkV6') -and (-not $_.IsIPv6LinkLocal) -and (-not $_.IsIPv6SiteLocal) }).'IPAddressToString'
                                    }
                                }
                                'isdisableable' {
                                    # This is used when looking up an Optional Feature.
                                    # This is $false for both available Optional Features and I can't find out how it's derived, so just statically assign it here.
                                    $Calculate_Later_Value = $false
                                }
                                'enabledscopes' {
                                    Write-Verbose ('{0}|EnabledScopes: Searching for EnabledScopes for: {1}' -f $Function_Name, $Result_Object['name'])
                                    $EnabledScopes_Search_Parameters = @{}
                                    $EnabledScopes_Search_Parameters['PageSize'] = $PageSize
                                    $EnabledScopes_Search_Parameters['SearchBase'] = $SearchBase
                                    $EnabledScopes_Search_Parameters['Properties'] = @('distinguishedname')
                                    $EnabledScopes_Search_Parameters['LDAPFilter'] = '(msds-enabledfeature={0})' -f $Result_Object['distinguishedname']

                                    Write-Verbose ('{0}|EnabledScopes: Calling Find-DSSRawObject' -f $Function_Name)
                                    $EnabledScopes_Search_Results = Find-DSSRawObject @Common_Search_Parameters @EnabledScopes_Search_Parameters

                                    if ($EnabledScopes_Search_Results) {
                                        $Calculate_Later_Value = $EnabledScopes_Search_Results.'distinguishedname'
                                    } else {
                                        $Calculate_Later_Value = @()
                                    }
                                }
                            }

                            Write-Verbose ('{0}|CalculateLater: Adding property: {1} - {2}' -f $Function_Name, $Property, $Calculate_Later_Value)
                            $Result_Object[$Property] = $Calculate_Later_Value
                        }
                    }

                    $Directory_Searcher_Result_To_Return.Add($Result_Object)
                }

                $Directory_Searcher_Result_To_Return
            }
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
