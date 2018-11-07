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

    # Taken from: https://social.technet.microsoft.com/wiki/contents/articles/12037.active-directory-get-aduser-default-and-extended-properties.aspx
    $UserAccountControl_Properties = @{
        'accountnotdelegated'                   = 'NOT_DELEGATED'
        'allowreversiblepasswordencryption'     = 'ENCRYPTED_TEXT_PWD_ALLOWED'
        'doesnotrequirepreauth'                 = 'DONT_REQ_PREAUTH'
        'enabled'                               = 'ACCOUNTDISABLE'
        'homedirrequired'                       = 'HOMEDIR_REQUIRED'
        'mnslogonaccount'                       = 'MNS_LOGON_ACCOUNT'
        'passwordneverexpires'                  = 'DONT_EXPIRE_PASSWORD'
        'passwordnotrequired'                   = 'PASSWD_NOTREQD'
        'smartcardlogonrequired'                = 'SMARTCARD_REQUIRED'
        'trustedfordelegation'                  = 'TRUSTED_FOR_DELEGATION'
        'trustedtoauthfordelegation'            = 'TRUSTED_TO_AUTH_FOR_DELEGATION'
        'usedeskeyonly'                         = 'USE_DES_KEY_ONLY'
    }
    $UserAccountControl_Computed_Properties = @(
        'lockedout'
        'passwordexpired'
    )

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

        # All the UserAccountControl properties are generated via flags to the single "useraccountcontrol" LDAP property.
        # So the 'useraccountcontrol' property is added to the search properties list if any of the relevant UserAccountControl properties are requested.
        $Properties_To_Add = New-Object -TypeName 'System.Collections.ArrayList'
        foreach ($Property in $Properties) {
            [void]$Properties_To_Add.Add($Property)
            if (($UserAccountControl_Properties.GetEnumerator().Name -contains $Property) -and ($Properties_To_Add -notcontains 'useraccountcontrol')) {
                [void]$Properties_To_Add.Add('useraccountcontrol')
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

                    # Reformat certain attribute types
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

                    # Add additional constructed properties from the UserAccountControl property.
                    if ($Current_Searcher_Result_Property -eq 'useraccountcontrol') {
                        Write-Verbose ('{0}|UserAccountControl property found, possibly adding constructed properties...' -f $Function_Name)
                        # Only output the 'useraccountcontrol' property if it is explicitly asked for.
                        if (($Properties -contains '*') -or ($Properties -contains 'useraccountcontrol')) {
                            Write-Verbose ('{0}|UserAccountControl property specified directly' -f $Function_Name)
                            $Result_Object[$Current_Searcher_Result_Property] = $Current_Searcher_Result_Value
                        }

                        # This does the following:
                        # - Looks through the 'useraccountcontrol' integer and extracts the flag(s) that this integer refers to.
                        # - Loops through all the properties specified to the function and if there is a match, it will do this:
                        #   - 1. Set a default bool value of $true if the property is named "enabled" and $false for everything else.
                        #   - 2. If the flag is set, then it will flip the bool value to the opposite.
                        $UserAccountControl_Attributes = [Enum]::Parse('userAccountControlFlags', $Current_Searcher_Result_Value)
                        Write-Verbose ('{0}|UAC: Attributes currently set: {1}' -f $Function_Name,($UserAccountControl_Attributes -join ' '))
                        $UserAccountControl_Properties.GetEnumerator() | ForEach-Object {
                            $UserAccountControl_Property_Name = $_.Name
                            $UserAccountControl_Property_Value = $_.Value
                            Write-Verbose ('{0}|UAC: Checking UAC property: {1}={2}' -f $Function_Name,$UserAccountControl_Property_Name,$UserAccountControl_Property_Value)
                            if (($Properties -contains '*') -or ($Properties -contains $UserAccountControl_Property_Name)) {
                                Write-Verbose ('{0}|UAC: Processing Property: {1}' -f $Function_Name,$UserAccountControl_Property_Name)
                                if ($UserAccountControl_Property_Name -eq 'enabled') {
                                    $UserAccountControl_Property_Return = $true
                                } else {
                                    $UserAccountControl_Property_Return = $false
                                }
                                Write-Verbose ('{0}|UAC: Default value for Property "{1}" is: {2}' -f $Function_Name,$UserAccountControl_Property_Name,$UserAccountControl_Property_Return)
                                if ($UserAccountControl_Attributes -match $UserAccountControl_Property_Value) {
                                    $UserAccountControl_Property_Return = -not $UserAccountControl_Property_Return
                                }
                                Write-Verbose ('{0}|UAC: Return value for Property "{1}" is: {2}' -f $Function_Name,$UserAccountControl_Property_Name,$UserAccountControl_Property_Return)
                                $Result_Object[$UserAccountControl_Property_Name] = $UserAccountControl_Property_Return
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

# Taken from:
# - https://github.com/zloeber/PSAD
# - https://support.microsoft.com/en-us/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro
Add-Type -TypeDefinition @"
    [System.Flags]
    public enum userAccountControlFlags {
        SCRIPT                          = 0x0000001,
        ACCOUNTDISABLE                  = 0x0000002,
        HOMEDIR_REQUIRED                = 0x0000008,
        LOCKOUT                         = 0x0000010,
        PASSWD_NOTREQD                  = 0x0000020,
        PASSWD_CANT_CHANGE              = 0x0000040,
        ENCRYPTED_TEXT_PWD_ALLOWED      = 0x0000080,
        TEMP_DUPLICATE_ACCOUNT          = 0x0000100,
        NORMAL_ACCOUNT                  = 0x0000200,
        INTERDOMAIN_TRUST_ACCOUNT       = 0x0000800,
        WORKSTATION_TRUST_ACCOUNT       = 0x0001000,
        SERVER_TRUST_ACCOUNT            = 0x0002000,
        DONT_EXPIRE_PASSWORD            = 0x0010000,
        MNS_LOGON_ACCOUNT               = 0x0020000,
        SMARTCARD_REQUIRED              = 0x0040000,
        TRUSTED_FOR_DELEGATION          = 0x0080000,
        NOT_DELEGATED                   = 0x0100000,
        USE_DES_KEY_ONLY                = 0x0200000,
        DONT_REQ_PREAUTH                = 0x0400000,
        PASSWORD_EXPIRED                = 0x0800000,
        TRUSTED_TO_AUTH_FOR_DELEGATION  = 0x1000000,
        PARTIAL_SECRETS_ACCOUNT         = 0x4000000,
    }
"@
