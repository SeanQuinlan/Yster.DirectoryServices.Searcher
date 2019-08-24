function Set-DSSUser {
    <#
    .SYNOPSIS
        Modifies an LDAP attribute of a User object from Active Directory.
    .DESCRIPTION
        Queries Active Directory for a specific user object and then modifies one or more attributes on this object.
        The object can be specified using one of the following
            - DistinguishedName
            - ObjectSID (SID)
            - ObjectGUID (GUID)
            - SAMAccountName
    .EXAMPLE
        Set-DSSUser -DistinguishedName 'CN=JSmith,OU=Marketing,OU=Accounts,DC=contoso,DC=com' -Replace @{DisplayName='Smith, Jacob'}

        Sets the DisplayName of the JSmith user, replacing any value that is already there.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/set-aduser
    #>

    [CmdletBinding(DefaultParameterSetName = 'DistinguishedName', SupportsShouldProcess = $true)]
    param(
        # The DistinguishedName of the user.
        [Parameter(Mandatory = $true, ParameterSetName = 'DistinguishedName')]
        [ValidateNotNullOrEmpty()]
        [Alias('DN')]
        [String]
        $DistinguishedName,

        # The ObjectSID of the user.
        [Parameter(Mandatory = $true, ParameterSetName = 'SID')]
        [ValidateNotNullOrEmpty()]
        [Alias('SID')]
        [String]
        $ObjectSID,

        # The ObjectGUID of the user.
        [Parameter(Mandatory = $true, ParameterSetName = 'GUID')]
        [ValidateNotNullOrEmpty()]
        [Alias('GUID')]
        [String]
        $ObjectGUID,

        # The SAMAccountName of the user.
        [Parameter(Mandatory = $true, ParameterSetName = 'SAM')]
        [ValidateNotNullOrEmpty()]
        [Alias('SAM')]
        [String]
        $SAMAccountName,

        # A property name and a value or set of values that will be removed from an existing multi-property value.
        # Multiple values for the same property can be separated by commas.
        # Multiple properties can also be specified by separating them with semi-colons.
        # See below for some examples:
        #
        # -Remove @{othertelephone='000-1111-2222'}
        # -Remove @{url='www.contoso.com','sales.contoso.com','intranet.contoso.com'}
        #
        # If specifying the Add, Clear, Remove and Replace parameters together, they are processed in this order:
        # ..Remove
        # ..Add
        # ..Replace
        # ..Clear
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [HashTable]
        $Remove,

        # A property name and a value or set of values that will be added to the existing property values.
        # Multiple values for the same property can be separated by commas.
        # Multiple properties can also be specified by separating them with semi-colons.
        # See below for some examples:
        #
        # -Add @{othertelephone='000-1111-2222'}
        # -Add @{url='www.contoso.com','sales.contoso.com','intranet.contoso.com'}
        #
        # If specifying the Add, Clear, Remove and Replace parameters together, they are processed in this order:
        # ..Remove
        # ..Add
        # ..Replace
        # ..Clear
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [HashTable]
        $Add,

        # A property or an array of properties to clear.
        # See below for some examples:
        #
        # -Clear Description
        # -Clear initials,givenname,displayname
        #
        # If specifying the Add, Clear, Remove and Replace parameters together, they are processed in this order:
        # ..Remove
        # ..Add
        # ..Replace
        # ..Clear
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Array]
        $Clear,

        # The value that will be set as the Company of the user.
        # An example of using this property is:
        #
        # -Company 'Contoso, Inc'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Company,

        # The value that will be set as the Description of the user.
        # An example of using this property is:
        #
        # -Description 'Joe Smith'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Description,

        # The value that will be set as the Division of the user.
        # An example of using this property is:
        #
        # -Division 'Marketing'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Division,

        # The value that will be set as the EmployeeID of the user.
        # An example of using this property is:
        #
        # -EmployeeID 'JSMITH41'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $EmployeeID,

        # The value that will be set as the EmployeeNumber of the user.
        # An example of using this property is:
        #
        # -EmployeeNumber '10380010'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $EmployeeNumber,

        # The value that will be set as the GivenName of the user.
        # An example of using this property is:
        #
        # -GivenName 'John'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('FirstName')]
        [String]
        $GivenName,

        # The value that will be set as the HomeDirectory of the user. This should be a local path or a UNC path with with a server and share specified.
        # An example of using this property is:
        #
        # -HomeDirectory 'D:\Profiles\HomeDir'
        # -HomeDirectory '\\fileserver01\home\jsmith'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $HomeDirectory,

        # The value that will be set as the HomeDrive of the user. This must be set to a drive letter, followed by a colon.
        # An example of using this property is:
        #
        # -HomeDrive 'H:'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $HomeDrive,

        # A property name and a value or set of values that will be used to replace the existing property values.
        # Multiple values for the same property can be separated by commas.
        # Multiple properties can also be specified by separating them with semi-colons.
        # See below for some examples:
        #
        # -Replace @{Description='Senior Manager'}
        # -Replace @{otherTelephone='000-0000-0000','111-1111-1111'}
        # -Replace @{givenname='John'; sn='Smith'; displayname='Smith, John'}
        #
        # If specifying the Add, Clear, Remove and Replace parameters together, they are processed in this order:
        # ..Remove
        # ..Add
        # ..Replace
        # ..Clear
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [HashTable]
        $Replace,

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
            [void]$PSBoundParameters.Remove('Server')
        }
        if ($PSBoundParameters.ContainsKey('Credential')) {
            $Common_Search_Parameters['Credential'] = $Credential
            [void]$PSBoundParameters.Remove('Credential')
        }

        $Default_LDAPFilter = '(objectclass=user)'
        if ($PSBoundParameters.ContainsKey('SAMAccountName')) {
            $LDAPFilter = '(&{0}(samaccountname={1}))' -f $Default_LDAPFilter, $SAMAccountName
            $Directory_Search_Type = 'SAMAccountName'
            $Directory_Search_Value = $SAMAccountName
            [void]$PSBoundParameters.Remove('SAMAccountName')
        } elseif ($PSBoundParameters.ContainsKey('DistinguishedName')) {
            $LDAPFilter = '(&{0}(distinguishedname={1}))' -f $Default_LDAPFilter, $DistinguishedName
            $Directory_Search_Type = 'DistinguishedName'
            $Directory_Search_Value = $DistinguishedName
            [void]$PSBoundParameters.Remove('DistinguishedName')
        } elseif ($PSBoundParameters.ContainsKey('ObjectSID')) {
            $LDAPFilter = '(&{0}(objectsid={1}))' -f $Default_LDAPFilter, $ObjectSID
            $Directory_Search_Type = 'ObjectSID'
            $Directory_Search_Value = $ObjectSID
            [void]$PSBoundParameters.Remove('ObjectSID')
        } else {
            $LDAPFilter = '(&{0}(objectguid={1}))' -f $Default_LDAPFilter, $ObjectGUID
            $Directory_Search_Type = 'ObjectGUID'
            $Directory_Search_Value = $ObjectGUID
            [void]$PSBoundParameters.Remove('ObjectGUID')
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
                    $Current_Value = Get-Variable -Name $Set_Choice -ValueOnly
                    if ($Set_Choice -eq 'Clear') {
                        $Current_Value | ForEach-Object {
                            if ($PSBoundParameters[$_]) {
                                $Conflicting_Parameter = $_
                            }
                        }
                    } else {
                        $Current_Value.GetEnumerator() | ForEach-Object {
                            if ($PSBoundParameters[$_.Name]) {
                                $Conflicting_Parameter = $_.Name
                            }
                        }
                    }
                    if ($Conflicting_Parameter) {
                        $Terminating_ErrorRecord_Parameters = @{
                            'Exception'    = 'System.ArgumentException'
                            'ID'           = 'DSS-{0}' -f $Function_Name
                            'Category'     = 'InvalidArgument'
                            'TargetObject' = $Object_Directory_Entry
                            'Message'      = 'Cannot specify attribute "{0}" as a direct parameter and via the Add/Remove/Replace/Clear parameters as well' -f $Conflicting_Parameter
                        }
                        $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                        $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                    } else {
                        $Set_Parameters[$Set_Choice] = $Current_Value
                        [void]$PSBoundParameters.Remove($Set_Choice)
                    }
                }
            }

            # Add any other bound parameters, excluding the ones in $All_CommonParameters.
            foreach ($Parameter_Key in $PSBoundParameters.Keys) {
                if ($All_CommonParameters -notcontains $Parameter_Key) {
                    $Set_Parameters['Replace'] += @{
                        $Parameter_Key = $PSBoundParameters[$Parameter_Key]
                    }
                }
            }

            if ($Set_Parameters.Count) {
                # Perform some additional validation on the supplied values. This needs to be done here in order to validate the values passed in via Add/Replace/Remove hashtables.
                foreach ($Choice in @('Replace', 'Add')) {
                    if ($Set_Parameters[$Choice]) {
                        $Set_Parameters_To_Validate += $Set_Parameters[$Choice].GetEnumerator()
                    }
                }
                foreach ($Parameter in $Set_Parameters_To_Validate) {
                    if ($Parameter.Name -eq 'HomeDrive') {
                        if ($Parameter.Value -notmatch '^[A-Z]{1}:') {
                            $Terminating_ErrorRecord_Parameters = @{
                                'Exception'    = 'System.ArgumentException'
                                'ID'           = 'DSS-{0}' -f $Function_Name
                                'Category'     = 'InvalidArgument'
                                'TargetObject' = $Parameter
                                'Message'      = 'HomeDrive value must be a single letter followed by a colon.'
                            }
                            $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                        }
                    }
                }

                $Set_Parameters['Action'] = 'Set'
                $Set_Parameters['Object'] = $Object_Directory_Entry
                Write-Verbose ('{0}|Calling Set-DSSRawObject' -f $Function_Name)
                Set-DSSRawObject @$Common_Search_Parameters @Set_Parameters
            } else {
                Write-Verbose ('{0}|No Set parameters provided, so doing nothing' -f $Function_Name)
            }
        } else {
            $Terminating_ErrorRecord_Parameters = @{
                'Exception'    = 'System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException'
                'ID'           = 'DSS-{0}' -f $Function_Name
                'Category'     = 'ObjectNotFound'
                'TargetObject' = $Object_Directory_Entry
                'Message'      = 'Cannot find User with {0} of "{1}"' -f $Directory_Search_Type, $Directory_Search_Value
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
