function Set-DSSObject {
    <#
    .SYNOPSIS
        Modifies an LDAP attribute of an object from Active Directory.
    .DESCRIPTION
        Queries Active Directory for a specific object and then modifies one or more attributes on this object.
        The object can be specified using one of the following
            - DistinguishedName
            - ObjectGUID (GUID)
    .EXAMPLE
        Set-DSSObject -DistinguishedName 'CN=SQL Servers,DC=Servers,DC=contoso,DC=com' -Replace @{Description='SQL Servers'}

        Sets the Description attribute of the "SQL Servers" object, replacing any value that is already there.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/set-adobject
    #>

    [CmdletBinding(DefaultParameterSetName = 'DistinguishedName', SupportsShouldProcess = $true)]
    param(
        # The DistinguishedName of the object.
        [Parameter(Mandatory = $true, ParameterSetName = 'DistinguishedName')]
        [ValidateNotNullOrEmpty()]
        [Alias('DN')]
        [String]
        $DistinguishedName,

        # The ObjectGUID of the object.
        [Parameter(Mandatory = $true, ParameterSetName = 'GUID')]
        [ValidateNotNullOrEmpty()]
        [Alias('GUID')]
        [String]
        $ObjectGUID,

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
        if ($PSBoundParameters.ContainsKey('Confirm')) {
            $Confirm_Parameters['Confirm'] = $Confirm
        }
        if ($PSBoundParameters.ContainsKey('WhatIf')) {
            $Confirm_Parameters['WhatIf'] = $WhatIf
        }

        if ($PSBoundParameters.ContainsKey('DistinguishedName')) {
            $LDAPFilter = '(distinguishedname={0})' -f $DistinguishedName
            $Directory_Search_Type = 'DistinguishedName'
            $Directory_Search_Value = $DistinguishedName
        } else {
            $LDAPFilter = '(objectguid={0})' -f $ObjectGUID
            $Directory_Search_Type = 'ObjectGUID'
            $Directory_Search_Value = $ObjectGUID
        }
        $Directory_Search_Parameters = @{
            'LDAPFilter'   = $LDAPFilter
            'OutputFormat' = 'DirectoryEntry'
        }

        $global:Object_Directory_Entry = Find-DSSRawObject @Common_Search_Parameters @Directory_Search_Parameters
        if ($Object_Directory_Entry) {
            $Set_Choices = @('Remove', 'Add', 'Replace', 'Clear')
            $Set_Parameters = @{}
            foreach ($Set_Choice in $Set_Choices) {
                if ($PSBoundParameters.ContainsKey($Set_Choice)) {
                    $Set_Parameters[$Set_Choice] = (Get-Variable -Name $Set_Choice -ValueOnly)
                    $Set_Parameter_Valid = $true
                }
            }

            if ($Set_Parameter_Valid -eq $true) {
                $Set_Parameters['Action'] = 'Set'
                $Set_Parameters['Object'] = $Object_Directory_Entry
                Write-Verbose ('{0}|Calling Set-DSSRawObject' -f $Function_Name)
                Set-DSSRawObject @$Common_Search_Parameters @Set_Parameters @Confirm_Parameters

            } else {
                Write-Verbose ('{0}|No Set parameters provided, so doing nothing' -f $Function_Name)
            }
        } else {
            $Terminating_ErrorRecord_Parameters = @{
                'Exception'    = 'System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException'
                'ID'           = 'DSS-{0}' -f $Function_Name
                'Category'     = 'ObjectNotFound'
                'TargetObject' = $Object_Directory_Entry
                'Message'      = 'Cannot find Object with {0} of "{1}"' -f $Directory_Search_Type, $Directory_Search_Value
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