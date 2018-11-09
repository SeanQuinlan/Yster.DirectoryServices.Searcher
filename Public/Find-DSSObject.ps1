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
        # An LDAP filter to use for the search.
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
        [ValidateSet('Base','OneLevel','Subtree')]
        [String]
        $SearchScope,

        # The properties of any results to return.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties = @('distinguishedname','objectclass','objectguid'),

        # The context to search - Domain or Forest.
        [Parameter(Mandatory = $false)]
        [ValidateSet('Domain','Forest')]
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
        'useraccountcontrol' = @{
            'accountnotdelegated'                   = '0x0100000'
            'allowreversiblepasswordencryption'     = '0x0000080'
            'doesnotrequirepreauth'                 = '0x0400000'
            'enabled'                               = '0x0000002'
            'homedirrequired'                       = '0x0000008'
            'mnslogonaccount'                       = '0x0020000'
            'passwordneverexpires'                  = '0x0010000'
            'passwordnotrequired'                   = '0x0000020'
            'smartcardlogonrequired'                = '0x0040000'
            'trustedfordelegation'                  = '0x0080000'
            'trustedtoauthfordelegation'            = '0x1000000'
            'usedeskeyonly'                         = '0x0200000'
        }
        'msds-user-account-control-computed' = @{
            'lockedout'                             = '0x0000010'
            'passwordexpired'                       = '0x0800000'
        }
    }

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name,$_.Key,($_.Value -join ' ')) }

    try {
        $Directory_Entry_Parameters = @{
            'Context' = $Context
        }
        if ($PSBoundParameters.ContainsKey('SearchBase')) {
            Write-Verbose ('{0}|Using SearchBase: {1}' -f $Function_Name,$SearchBase)
            $Directory_Entry_Parameters.SearchBase = $SearchBase
        }
        if ($PSBoundParameters.ContainsKey('Server')) {
            Write-Verbose ('{0}|Using Server: {1}' -f $Function_Name,$Server)
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

        # The relevant "UserAccountControl_Calculated" property is added to the search properties list if any of the calculated properties are requested.
        $Properties_To_Add = New-Object -TypeName 'System.Collections.ArrayList'
        foreach ($Property in $Properties) {
            [void]$Properties_To_Add.Add($Property)
            foreach ($UAC_Calculated_Property in $UAC_Calculated_Properties.GetEnumerator().Name) {
                if (($UAC_Calculated_Properties.$UAC_Calculated_Property.GetEnumerator().Name -contains $Property) -and ($Properties_To_Add -notcontains $UAC_Calculated_Property)) {
                    [void]$Properties_To_Add.Add($UAC_Calculated_Property)
                }
            }
            if ($Property -eq '*') {
                foreach ($Additional_Wildcard_Property in $Additional_Wildcard_Properties) {
                    [void]$Properties_To_Add.Add($Additional_Wildcard_Property)
                }
            }
        }
        Write-Verbose ('{0}|Adding Properties: {1}' -f $Function_Name,($Properties_To_Add -join ' '))
        $Directory_Searcher.PropertiesToLoad.AddRange($Properties_To_Add)
        if ($PSBoundParameters.ContainsKey('SearchScope')) {
            Write-Verbose ('{0}|Adding SearchScope: {1}' -f $Function_Name,$SearchScope)
            $Directory_Searcher.SearchScope = $SearchScope
        }

        Write-Verbose ('{0}|Performing search...' -f $Function_Name)
        $Directory_Searcher_Results = $Directory_Searcher.FindAll()
        if ($Directory_Searcher_Results) {
            Write-Verbose ('{0}|Found {1} result(s)' -f $Function_Name,$Directory_Searcher_Results.Count)
            $Directory_Searcher_Results_To_Return = New-Object -TypeName 'System.Collections.ArrayList'
            foreach ($Directory_Searcher_Result in $Directory_Searcher_Results) {
                $Result_Object = @{}
                $Directory_Searcher_Result.Properties.GetEnumerator() | Sort-Object 'Name' | ForEach-Object {
                    $Current_Searcher_Result_Property   = $_.Name
                    $Current_Searcher_Result_Value      = $($_.Value)
                    $Current_Searcher_Result_Syntax     = Get-DSSAttributeSyntax -Name $Current_Searcher_Result_Property
                    Write-Verbose ('{0}|Property={1} Syntax={2} Value={3}' -f $Function_Name,$Current_Searcher_Result_Property,$Current_Searcher_Result_Syntax,$Current_Searcher_Result_Value)

                    # Reformat certain attribute types:
                    switch ($Current_Searcher_Result_Syntax) {
                        # GUID
                        '2.5.5.10' {
                            Write-Verbose ('{0}|Reformatting to GUID object: {1}' -f $Function_Name,$Current_Searcher_Result_Property)
                            $Current_Searcher_Result_Value = New-Object 'System.Guid' -ArgumentList @(,$Current_Searcher_Result_Value)
                        }

                        # SID
                        '2.5.5.17' {
                            Write-Verbose ('{0}|Reformatting to SID object: {1}' -f $Function_Name,$Current_Searcher_Result_Property)
                            $Current_Searcher_Result_Value = New-Object 'System.Security.Principal.SecurityIdentifier' -ArgumentList @($Current_Searcher_Result_Value,0)
                        }
                    }

                    # Add additional constructed properties from the "UserAccountControl" properties.
                    if ($UAC_Calculated_Properties.GetEnumerator().Name -contains $Current_Searcher_Result_Property) {
                        Write-Verbose ('{0}|UAC property found: {1}={2}' -f $Function_Name,$Current_Searcher_Result_Property,$Current_Searcher_Result_Value)
                        # Only output the "UserAccountControl" property if it is explicitly requested.
                        if ($Properties -contains $Current_Searcher_Result_Property) {
                            Write-Verbose ('{0}|UAC property specified directly: {0}' -f $Function_Name,$Current_Searcher_Result_Property)
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
                            Write-Verbose ('{0}|UAC: Checking UAC calculated property: {1}={2}' -f $Function_Name,$UAC_Calculated_Property_Name,$UAC_Calculated_Property_Flag)
                            if ($Properties -contains $UAC_Calculated_Property_Name) {
                                Write-Verbose ('{0}|UAC: Processing property: {1}' -f $Function_Name,$UAC_Calculated_Property_Name)
                                if ($UAC_Calculated_Property_Name -eq 'enabled') {
                                    $UAC_Calculated_Property_Return = $true
                                } else {
                                    $UAC_Calculated_Property_Return = $false
                                }
                                if (($Current_Searcher_Result_Value -band $UAC_Calculated_Property_Flag) -eq $UAC_Calculated_Property_Flag) {
                                    $UAC_Calculated_Property_Return = -not $UAC_Calculated_Property_Return
                                }
                                Write-Verbose ('{0}|UAC: Return value for "{1}" is "{2}"' -f $Function_Name,$UAC_Calculated_Property_Name,$UAC_Calculated_Property_Return)
                                $Result_Object[$UAC_Calculated_Property_Name] = $UAC_Calculated_Property_Return
                            }
                        }
                    } else {
                        $Result_Object[$Current_Searcher_Result_Property] = $Current_Searcher_Result_Value
                    }
                }

                # Sort results and then add to a new hashtable, as PSObject requires a hashtable as Property. GetEnumerator() piped into Sort-Object changes the output to an array.
                $Result_Object_Sorted = [ordered]@{}
                $Result_Object.GetEnumerator() | Sort-Object -Property 'Name' | ForEach-Object {
                    $Result_Object_Sorted[$_.Name] = $_.Value
                }
                $Directory_Searcher_Result_Object = New-Object -TypeName 'System.Management.Automation.PSObject' -Property $Result_Object_Sorted
                [void]$Directory_Searcher_Results_To_Return.Add($Directory_Searcher_Result_Object)
            }
            # Return the search results object
            $Directory_Searcher_Results_To_Return
        } else {
            Write-Verbose ('{0}|No results found!' -f $Function_Name)
        }

    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
