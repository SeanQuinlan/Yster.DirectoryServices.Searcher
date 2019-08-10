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
            'SearchBase' = 'OU=RootOU,DC=root,DC=lab'
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

        # Whether to return deleted objects in the search results.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $IncludeDeletedObjects,

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

        # The format of the output.
        [Parameter(Mandatory = $false)]
        [ValidateSet('DirectoryEntry', 'Hashtable')]
        [String]
        $OutputFormat = 'Hashtable',

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
        'adspath'
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
        'member'                       = 'members'
        'minpwdage'                    = 'minpasswordage'
        'minpwdlength'                 = 'minpasswordlength'
        'mobile'                       = 'mobilephone'
        'msds-alloweddnssuffixes'      = 'alloweddnssuffixes'
        'msds-assignedauthnpolicy'     = 'authenticationpolicy'
        'msds-assignedauthnpolicysilo' = 'authenticationpolicysilo'
        'msds-hostserviceaccount'      = 'serviceaccount'
        'msds-optionalfeatureguid'     = 'featureguid'
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

    # The Get-AD* cmdlets also add a number of other useful properties based on calculations of other properties.
    # Like creating a datetime object from an integer property.
    $Useful_Calculated_Properties = @{
        # Delegation properties
        'msds-allowedtoactonbehalfofotheridentity' = 'principalsallowedtodelegatetoaccount'

        # Domain properties
        'gplink'                                   = 'linkedgrouppolicyobjects'
        'msds-optionalfeatureflags'                = 'featurescope'
        'msds-requireddomainbehaviorversion'       = 'requireddomainmode'
        'msds-requiredforestbehaviorversion'       = 'requiredforestmode'

        # Encryption properties
        'msds-supportedencryptiontypes'            = @('compoundidentitysupported', 'kerberosencryptiontype')

        # Group properties
        'grouptype'                                = @('groupcategory', 'groupscope')
        'primarygroupid'                           = 'primarygroup'

        # Security properties
        'ntsecuritydescriptor'                     = @('cannotchangepassword', 'protectedfromaccidentaldeletion')

        # Time properties (Note: add to regex match in later switch statement)
        'accountexpires'                           = 'accountexpirationdate'
        'badpasswordtime'                          = 'lastbadpasswordattempt'
        'lastlogontimestamp'                       = 'lastlogondate'
        'lockouttime'                              = 'accountlockouttime'
        'pwdlastset'                               = 'passwordlastset'

        # Properties which are returned as TimeSpan objects, based on an integer stored in Active Directory.
        'msds-logontimesyncinterval'               = 'lastlogonreplicationinterval'
    }

    # Like the $Useful_Calculated_Properties above, these are also calculated based on another property, but require some additional calculation on the sub-property as well.
    $Useful_Calculated_SubProperties = @{
        # A number of properties returned by the AD Cmdlets are calculated based on flags to one of the UserAccountControl LDAP properties.
        # The list of flags and their corresponding values are taken from here:
        # - https://support.microsoft.com/en-us/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro
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

        # Get-ADDomain provides a number of "Container" properties which are calculated from the WellknownObjects or OtherWellknownObjects properties.
        # - Values taken from https://support.microsoft.com/en-gb/help/324949/redirecting-the-users-and-computers-containers-in-active-directory-dom
        'wellknownobjects'                   = @{
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
        'otherwellknownobjects'              = @{
            'keyscontainer'                   = 'B:32:683A24E2E8164BD3AF86AC3C2CF3F981:'
            'managedserviceaccountscontainer' = 'B:32:1EB93889E40C45DF9F0C64D23BBB6237:'
        }

        # These are calculated from the 'pwdproperties' property.
        # - Values taken from: https://docs.microsoft.com/en-us/windows/desktop/adschema/a-pwdproperties
        'pwdproperties'                      = @{
            'complexityenabled'           = '0x01'
            'reversibleencryptionenabled' = '0x10'
        }
    }

    # Some additional flags to the 'msds-supportedencryptiontypes' property which don't form part of the ADKerberosEncryptionTypes Enum.
    # - Taken from https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919
    $Additional_Encryption_Types = @{
        'FAST-Supported'                    = '0x10000'
        'Compound-Identity-Supported'       = '0x20000'
        'Claims-Supported'                  = '0x40000'
        'Resource-SID-Compression-Disabled' = '0x80000'
    }

    # A regular expression to determine if a property needs to be paged to return all values.
    $Paging_Regex = '\;range=(\d+)-(.*)'

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
        foreach ($Property in $Properties) {
            $Properties_To_Add.Add($Property)

            $Combined_Calculated_Properties = $Microsoft_Alias_Properties + $Useful_Calculated_Properties
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
            if ($OutputFormat -eq 'DirectoryEntry') {
                Write-Verbose ('{0}|Returning {1}' -f $Function_Name, $OutputFormat)
                $Directory_Searcher_Results | ForEach-Object {
                    $_.GetDirectoryEntry()
                }
            } elseif ($OutputFormat -eq 'HashTable') {
                Write-Verbose ('{0}|Returning {1}' -f $Function_Name, $OutputFormat)
                $Directory_Searcher_Result_To_Return = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'
                foreach ($Directory_Searcher_Result in $Directory_Searcher_Results) {
                    Write-Verbose ('{0}|Reformatting result properties order' -f $Function_Name)
                    $Reformatted_Directory_Searcher_Result = [Ordered]@{ }
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

                    $Result_Object = @{ }
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
                                $Paging_Start = ($Paging_Start -as [int]) + $Paging_Total
                                $Paging_End = ($Paging_End -as [int]) + $Paging_Total
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

                                    Switch -Regex ($Useful_Calculated_Property_Name) {
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
                                        'linkedgrouppolicyobjects' {
                                            # Convert the "gplink" string property into an array of strings, selecting just the Group Policy DistinguishedName.
                                            $Regex_GPLink = [System.Text.RegularExpressions.Regex]'\[LDAP://(.*?)\;\d\]'
                                            $Useful_Calculated_Property_Value = $Regex_GPLink.Matches($Current_Searcher_Result_Value) | ForEach-Object { $_.Groups[1].Value }
                                        }
                                        'featurescope' {
                                            $Useful_Calculated_Property_Value = $OptionalFeature_Scope_Table[$Current_Searcher_Result_Value.ToString()]
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
                                            $Useful_Calculated_Property_Value = [Enum]::Parse('ADKerberosEncryptionType', $Current_Searcher_Result_Value)
                                        }

                                        # Group properties
                                        'groupscope' {
                                            if (($Current_Searcher_Result_Value -bor 2) -eq $Current_Searcher_Result_Value) {
                                                $Useful_Calculated_Property_Value = 'Global'
                                            } elseif (($Current_Searcher_Result_Value -bor 4) -eq $Current_Searcher_Result_Value) {
                                                $Useful_Calculated_Property_Value = 'Domain Local'
                                            } elseif (($Current_Searcher_Result_Value -bor 8) -eq $Current_Searcher_Result_Value) {
                                                $Useful_Calculated_Property_Value = 'Universal'
                                            } else {
                                                $Useful_Calculated_Property_Value = 'Unknown'
                                            }
                                        }
                                        'groupcategory' {
                                            if ($Current_Searcher_Result_Value -lt 0) {
                                                $Useful_Calculated_Property_Value = 'Security'
                                            } else {
                                                $Useful_Calculated_Property_Value = 'Distribution'
                                            }
                                        }
                                        'primarygroup' {
                                            # Convert the PrimaryGroupID to a full ObjectSID property, by using the AccountDomainSid sub-property of the ObjectSID property of the user and appending the PrimaryGroupID.
                                            $PrimaryGroup_SID = '{0}-{1}' -f $Result_Object['objectsid'].AccountDomainSid.Value, $Current_Searcher_Result_Value
                                            $Group_Search_Parameters = @{ }
                                            $Group_Search_Parameters['ObjectSID'] = $PrimaryGroup_SID
                                            $Useful_Calculated_Property_Value = (Get-DSSGroup @Common_Search_Parameters @Group_Search_Parameters).'distinguishedname'
                                        }

                                        # Security properties
                                        'cannotchangepassword' {
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
                                                    Write-Verbose ('{0}|Security: CannotChangePassword: Found correct permission for "Everyone" group: {1}' -f $Function_Name, $ChangePassword_Identity_Everyone)
                                                    $ChangePassword_Identity_Everyone_Correct = $true
                                                }
                                                if (($ChangePassword_Rule.IdentityReference -eq $ChangePassword_Identity_Self) -and ($ChangePassword_Rule.AccessControlType -eq 'Deny')) {
                                                    Write-Verbose ('{0}|Security: CannotChangePassword: Found correct permission for "Self" user: {1}' -f $Function_Name, $ChangePassword_Identity_Self)
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
                                            $AccidentalDeletion_Rights = 'DeleteTree, Delete'
                                            $AccidentalDeletion_Identity_Everyone_SID = New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList ([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
                                            $AccidentalDeletion_Identity_Everyone = $AccidentalDeletion_Identity_Everyone_SID.Translate([System.Security.Principal.NTAccount]).Value
                                            $AccidentalDeletion_Rule = $Current_Searcher_Result_Value.Access | Where-Object { ($_.ActiveDirectoryRights -match $AccidentalDeletion_Rights) -and ($_.IdentityReference -eq $AccidentalDeletion_Identity_Everyone) }
                                            if (($AccidentalDeletion_Rule.Count -eq 1) -and ($AccidentalDeletion_Rule.AccessControlType -eq 'Deny')) {
                                                Write-Verbose ('{0}|Security: AccidentalDeletion correct: Permission: {1} | Group: {2} | Count: {3}' -f $Function_Name, $AccidentalDeletion_Rule.AccessControlType, $AccidentalDeletion_Identity_Everyone, $AccidentalDeletion_Rule.Count)
                                                $Useful_Calculated_Property_Value = $true
                                            } else {
                                                Write-Verbose ('{0}|Security: AccidentalDeletion incorrect: Permission: {1} | Group: {2} | Count: {3}' -f $Function_Name, $AccidentalDeletion_Rule.AccessControlType, $AccidentalDeletion_Identity_Everyone, $AccidentalDeletion_Rule.Count)
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

                                    Switch -Regex ($Current_Searcher_Result_Property) {
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
                            $Result_Object[$Current_Searcher_Result_Property] = $Current_Searcher_Result_Value
                        }
                    }

                    # Add the object to the return array.
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
