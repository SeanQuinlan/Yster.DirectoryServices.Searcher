function Get-DSSRootDSE {
    <#
    .SYNOPSIS
        Gets the special RootDSE object from the directory server.
    .DESCRIPTION
        Retrieves the RootDSE object which provides information about the directory schema, version, supported capabilities and other LDAP server details.
    .EXAMPLE
        (Get-DSSRootDSE).schemaNamingContext

        This returns the naming context (DistinguishedName) of the Schema container.
    .EXAMPLE
        $DomainDN = (Get-DSSRootDSE).defaultNamingContext

        Returns the DistinguishedName of the Active Directory domain.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/get-adrootdse
    #>

    [CmdletBinding()]
    param(
        # The credential to use for access to perform the required action.
        # This credential can be provided in the form of a username, DOMAIN\username or as a PowerShell credential object.
        # In the case of a username or DOMAIN\username, you will be prompted to supply the password.
        # Some examples of using this property are:
        #
        # -Credential jsmith
        # -Credential 'CONTOSO\jsmith'
        #
        # $Creds = Get-Credential
        # -Credential $Creds
        [Parameter(Mandatory = $false)]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        # The server or domain to connect to.
        # See below for some examples:
        #
        # -Server DC01
        # -Server 'dc01.contoso.com'
        # -Server CONTOSO
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Server
    )

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    try {
        $Directory_Entry_Parameters = @{
            'Context'    = 'Domain'
            'SearchBase' = 'RootDSE'
        }
        if ($PSBoundParameters.ContainsKey('Server')) {
            $Directory_Entry_Parameters['Server'] = $Server
        }
        if ($PSBoundParameters.ContainsKey('Credential')) {
            $Directory_Entry_Parameters['Credential'] = $Credential
        }
        $Directory_Entry = Get-DSSDirectoryEntry @Directory_Entry_Parameters

        # Format the DirectoryEntry object to match that returned from Find-DSSRawObject.
        Write-Verbose ('{0}|Formatting result' -f $Function_Name)
        $Results_To_Return = @{}
        $Directory_Entry.Properties.PropertyNames | ForEach-Object {
            $RootDSE_Property = $_
            $RootDSE_Value = $($Directory_Entry.$_)
            Write-Verbose ('{0}|Property={1} Value={2}' -f $Function_Name, $RootDSE_Property, $RootDSE_Value)

            if ($RootDSE_Property -eq 'domaincontrollerfunctionality') {
                $Results_To_Return[$RootDSE_Property] = $DomainControllerMode_Table[$RootDSE_Value]
            } elseif ($RootDSE_Property -eq 'domainfunctionality') {
                $Results_To_Return[$RootDSE_Property] = $DomainMode_Table[$RootDSE_Value]
            } elseif ($RootDSE_Property -eq 'forestfunctionality') {
                $Results_To_Return[$RootDSE_Property] = $ForestMode_Table[$RootDSE_Value]
            } elseif (($RootDSE_Property -eq 'supportedcapabilities') -or ($RootDSE_Property -eq 'supportedcontrol')) {
                if ($RootDSE_Property -eq 'supportedcapabilities') {
                    $Table_Name = 'LDAP_Capabilities_Table'
                } else {
                    $Table_Name = 'LDAP_Extended_Controls'
                }

                $Supported_Array = New-Object -TypeName System.Collections.Generic.List[object]
                foreach ($Value_Entry in $RootDSE_Value) {
                    (Get-Variable -Name $Table_Name -ValueOnly).GetEnumerator() | Where-Object { $_.Value -eq $Value_Entry } | ForEach-Object {
                        $Supported_Array_Entry = [pscustomobject]@{
                            'Value'       = $_.Value
                            'DisplayName' = $_.Name
                        }
                    }
                    $Supported_Array.Add($Supported_Array_Entry)
                }
                $Results_To_Return[$RootDSE_Property] = $Supported_Array
            } else {
                $Results_To_Return[$RootDSE_Property] = $RootDSE_Value
            }
        }

        $Results_To_Return | ConvertTo-SortedPSObject

    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}

# From: https://docs.microsoft.com/en-us/dotnet/api/microsoft.activedirectory.management.addomaincontrollermode?view=activedirectory-management-10.0
$DomainControllerMode_Table = @{
    '0' = 'Windows2000'
    '2' = 'Windows2003'
    '3' = 'Windows2008'
    '4' = 'Windows2008R2'
    '5' = 'Windows2012'
    '6' = 'Windows2012R2'
    '7' = 'Windows2016'
}

# From: https://docs.microsoft.com/en-us/dotnet/api/microsoft.activedirectory.management.addomainmode?view=activedirectory-management-10.0
$DomainMode_Table = @{
    '0' = 'Windows2000Domain'
    '1' = 'Windows2003InterimDomain'
    '2' = 'Windows2003Domain'
    '3' = 'Windows2008Domain'
    '4' = 'Windows2008R2Domain'
    '5' = 'Windows2012Domain'
    '6' = 'Windows2012R2Domain'
    '7' = 'Windows2016Domain'
}

# From: https://docs.microsoft.com/en-us/dotnet/api/microsoft.activedirectory.management.adforestmode?view=activedirectory-management-10.0
$ForestMode_Table = @{
    '0' = 'Windows2000Forest'
    '1' = 'Windows2003InterimForest'
    '2' = 'Windows2003Forest'
    '3' = 'Windows2008Forest'
    '4' = 'Windows2008R2Forest'
    '5' = 'Windows2012Forest'
    '6' = 'Windows2012R2Forest'
    '7' = 'Windows2016Forest'
}

# From: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3ed61e6c-cfdc-487d-9f02-5a3397be3772
$LDAP_Capabilities_Table = @{
    'LDAP_CAP_ACTIVE_DIRECTORY_OID'                 = '1.2.840.113556.1.4.800'
    'LDAP_CAP_ACTIVE_DIRECTORY_V51_OID'             = '1.2.840.113556.1.4.1670'
    'LDAP_CAP_ACTIVE_DIRECTORY_LDAP_INTEG_OID'      = '1.2.840.113556.1.4.1791'
    'LDAP_CAP_ACTIVE_DIRECTORY_ADAM_OID'            = '1.2.840.113556.1.4.1851'
    'LDAP_CAP_ACTIVE_DIRECTORY_ADAM_DIGEST_OID'     = '1.2.840.113556.1.4.1880'
    'LDAP_CAP_ACTIVE_DIRECTORY_PARTIAL_SECRETS_OID' = '1.2.840.113556.1.4.1920'
    'LDAP_CAP_ACTIVE_DIRECTORY_V60_OID'             = '1.2.840.113556.1.4.1935'
    'LDAP_CAP_ACTIVE_DIRECTORY_V61_R2_OID'          = '1.2.840.113556.1.4.2080'
    'LDAP_CAP_ACTIVE_DIRECTORY_W8_OID'              = '1.2.840.113556.1.4.2237'
}

# From: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3c5e87db-4728-4f29-b164-01dd7d7391ea
$LDAP_Extended_Controls = @{
    'LDAP_PAGED_RESULT_OID_STRING'            =	'1.2.840.113556.1.4.319'
    'LDAP_SERVER_CROSSDOM_MOVE_TARGET_OID'    = '1.2.840.113556.1.4.521'
    'LDAP_SERVER_DIRSYNC_OID'                 = '1.2.840.113556.1.4.841'
    'LDAP_SERVER_DOMAIN_SCOPE_OID'            = '1.2.840.113556.1.4.1339'
    'LDAP_SERVER_EXTENDED_DN_OID'             = '1.2.840.113556.1.4.529'
    'LDAP_SERVER_GET_STATS_OID'               = '1.2.840.113556.1.4.970'
    'LDAP_SERVER_LAZY_COMMIT_OID'             = '1.2.840.113556.1.4.619'
    'LDAP_SERVER_PERMISSIVE_MODIFY_OID'       = '1.2.840.113556.1.4.1413'
    'LDAP_SERVER_NOTIFICATION_OID'            = '1.2.840.113556.1.4.528'
    'LDAP_SERVER_RESP_SORT_OID'               = '1.2.840.113556.1.4.474'
    'LDAP_SERVER_SD_FLAGS_OID'                = '1.2.840.113556.1.4.801'
    'LDAP_SERVER_SEARCH_OPTIONS_OID'          = '1.2.840.113556.1.4.1340'
    'LDAP_SERVER_SORT_OID'                    = '1.2.840.113556.1.4.473'
    'LDAP_SERVER_SHOW_DELETED_OID'            = '1.2.840.113556.1.4.417'
    'LDAP_SERVER_TREE_DELETE_OID'             = '1.2.840.113556.1.4.805'
    'LDAP_SERVER_VERIFY_NAME_OID'             = '1.2.840.113556.1.4.1338'
    'LDAP_CONTROL_VLVREQUEST'                 =	'2.16.840.1.113730.3.4.9'
    'LDAP_CONTROL_VLVRESPONSE'                =	'2.16.840.1.113730.3.4.10'
    'LDAP_SERVER_ASQ_OID'                     = '1.2.840.113556.1.4.1504'
    'LDAP_SERVER_QUOTA_CONTROL_OID'           = '1.2.840.113556.1.4.1852'
    'LDAP_SERVER_RANGE_OPTION_OID'            = '1.2.840.113556.1.4.802'
    'LDAP_SERVER_SHUTDOWN_NOTIFY_OID'         = '1.2.840.113556.1.4.1907'
    'LDAP_SERVER_FORCE_UPDATE_OID'            = '1.2.840.113556.1.4.1974'
    'LDAP_SERVER_RANGE_RETRIEVAL_NOERR_OID'   = '1.2.840.113556.1.4.1948'
    'LDAP_SERVER_RODC_DCPROMO_OID'            = '1.2.840.113556.1.4.1341'
    'LDAP_SERVER_DN_INPUT_OID'                = '1.2.840.113556.1.4.2026'
    'LDAP_SERVER_SHOW_DEACTIVATED_LINK_OID'   = '1.2.840.113556.1.4.2065'
    'LDAP_SERVER_SHOW_RECYCLED_OID'           = '1.2.840.113556.1.4.2064'
    'LDAP_SERVER_POLICY_HINTS_DEPRECATED_OID' = '1.2.840.113556.1.4.2066'
    'LDAP_SERVER_DIRSYNC_EX_OID'              = '1.2.840.113556.1.4.2090'
    'LDAP_SERVER_UPDATE_STATS_OID'            = '1.2.840.113556.1.4.2205'
    'LDAP_SERVER_TREE_DELETE_EX_OID'          = '1.2.840.113556.1.4.2204'
    'LDAP_SERVER_SEARCH_HINTS_OID'            = '1.2.840.113556.1.4.2206'
    'LDAP_SERVER_EXPECTED_ENTRY_COUNT_OID'    = '1.2.840.113556.1.4.2211'
    'LDAP_SERVER_POLICY_HINTS_OID'            = '1.2.840.113556.1.4.2239'
    'LDAP_SERVER_SET_OWNER_OID'               = '1.2.840.113556.1.4.2255'
    'LDAP_SERVER_BYPASS_QUOTA_OID'            = '1.2.840.113556.1.4.2256'
    'LDAP_SERVER_LINK_TTL_OID'                = '1.2.840.113556.1.4.2309'
    'LDAP_SERVER_SET_CORRELATION_ID_OID'      = '1.2.840.113556.1.4.2330'
    'LDAP_SERVER_THREAD_TRACE_OVERRIDE_OID'   = '1.2.840.113556.1.4.2354'
}
