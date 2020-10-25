function Add-DSSGroupMember {
    <#
    .SYNOPSIS
        Adds one or more objects to a group in Active Directory.
    .DESCRIPTION
        Queries Active Directory for a specific group object, based on one of the following specified parameters, and adds the object(s) to that group:
            - DistinguishedName
            - ObjectSID (SID)
            - ObjectGUID (GUID)
            - SAMAccountName
    .EXAMPLE
        Add-DSSGroupMember -ObjectSID 'S-1-5-21-3515480276-2049723633-1306762111-1103' -Members 'Jsmith','PJones','RWalters'

        Adds the above 3 users to the group with the specified SID.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/add-adgroupmember
    #>

    [CmdletBinding(DefaultParameterSetName = 'SAM', SupportsShouldProcess = $true)]
    param(
        # The directory context to search - Domain or Forest. By default this will search within the domain only.
        # If you want to search the entire directory, specify "Forest" for this parameter and the search will be performed on a Global Catalog server, targetting the entire forest.
        # An example of using this property is:
        #
        # -Context 'Forest'
        [Parameter(Mandatory = $false)]
        [ValidateSet('Domain', 'Forest')]
        [String]
        $Context = 'Domain',

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

        # The DistinguishedName of the group.
        [Parameter(Mandatory = $true, ParameterSetName = 'DistinguishedName')]
        [ValidateNotNullOrEmpty()]
        [Alias('DN')]
        [String]
        $DistinguishedName,

        # A member or list of members to add to the group.
        # Some examples of using this property are:
        #
        # -Members 'rsmith'
        # -Members 'rsmith','jjones'
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias('Member')]
        [String[]]
        $Members,

        # The ObjectGUID of the group.
        [Parameter(Mandatory = $true, ParameterSetName = 'GUID')]
        [ValidateNotNullOrEmpty()]
        [Alias('GUID')]
        [String]
        $ObjectGUID,

        # The ObjectSID of the group.
        [Parameter(Mandatory = $true, ParameterSetName = 'SID')]
        [ValidateNotNullOrEmpty()]
        [Alias('SID')]
        [String]
        $ObjectSID,

        # The SAMAccountName of the group.
        [Parameter(Mandatory = $true, ParameterSetName = 'SAM')]
        [ValidateNotNullOrEmpty()]
        [Alias('SAM')]
        [String]
        $SAMAccountName,

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
        $Common_Search_Parameters = @{
            'Context' = $Context
        }
        if ($PSBoundParameters.ContainsKey('Server')) {
            $Common_Search_Parameters['Server'] = $Server
        }
        if ($PSBoundParameters.ContainsKey('Credential')) {
            $Common_Search_Parameters['Credential'] = $Credential
        }

        $Confirm_Parameters = @{}
        # This will add the -Confirm parameter if ConfirmPreference is set high enough.
        # The Set-DSSRawObject doesn't have a default ConfirmImpact set, so this passes the ConfirmImpact from this function if required.
        if (-not $PSBoundParameters.ContainsKey('Confirm')) {
            $ConfirmImpact = 'Medium'
            if ([System.Management.Automation.ConfirmImpact]::$ConfirmImpact.Value__ -ge [System.Management.Automation.ConfirmImpact]::$ConfirmPreference.Value__) {
                Write-Verbose ('{0}|Adding Confirm parameter' -f $Function_Name)
                $Confirm_Parameters['Confirm'] = $True
            }
        }
        if ($PSBoundParameters.ContainsKey('WhatIf')) {
            $Confirm_Parameters['WhatIf'] = $WhatIf
        }

        $Default_LDAPFilter = '(objectclass=group)'
        if ($PSBoundParameters.ContainsKey('SAMAccountName')) {
            $LDAPFilter = '(&{0}(samaccountname={1}))' -f $Default_LDAPFilter, $SAMAccountName
            $Directory_Search_Type = 'SAMAccountName'
            $Directory_Search_Value = $SAMAccountName
        } elseif ($PSBoundParameters.ContainsKey('DistinguishedName')) {
            $LDAPFilter = '(&{0}(distinguishedname={1}))' -f $Default_LDAPFilter, $DistinguishedName
            $Directory_Search_Type = 'DistinguishedName'
            $Directory_Search_Value = $DistinguishedName
        } elseif ($PSBoundParameters.ContainsKey('ObjectSID')) {
            $LDAPFilter = '(&{0}(objectsid={1}))' -f $Default_LDAPFilter, $ObjectSID
            $Directory_Search_Type = 'ObjectSID'
            $Directory_Search_Value = $ObjectSID
        } else {
            $LDAPFilter = '(&{0}(objectguid={1}))' -f $Default_LDAPFilter, $ObjectGUID
            $Directory_Search_Type = 'ObjectGUID'
            $Directory_Search_Value = $ObjectGUID
        }
        $Directory_Search_Parameters = @{
            'LDAPFilter'   = $LDAPFilter
            'OutputFormat' = 'DirectoryEntry'
        }

        $Object_Directory_Entry = Find-DSSRawObject @Common_Search_Parameters @Directory_Search_Parameters
        if ($Object_Directory_Entry) {
            $Set_Parameters = @{
                'Action'  = 'AddGroupMember'
                'Object'  = $Object_Directory_Entry
                'Members' = $Members
            }
            Write-Verbose ('{0}|Calling Set-DSSRawObject' -f $Function_Name)
            Set-DSSRawObject @Common_Search_Parameters @Set_Parameters @Confirm_Parameters
        } else {
            $Terminating_ErrorRecord_Parameters = @{
                'Exception'    = 'System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException'
                'ID'           = 'DSS-{0}' -f $Function_Name
                'Category'     = 'ObjectNotFound'
                'TargetObject' = $Object_Directory_Entry
                'Message'      = 'Cannot find Group with {0} of "{1}"' -f $Directory_Search_Type, $Directory_Search_Value
            }
            $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
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
