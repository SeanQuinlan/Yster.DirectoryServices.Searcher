function New-DSSRawObject {
    <#
    .SYNOPSIS
        Creates a new object in Active Directory.
    .DESCRIPTION
        Performs the required modification to the object that is passed in via the $Object parameter.

        This is not meant to be used as an interactive function; it is used as a worker function by many of the other higher-level functions.
    .EXAMPLE
        $FindObject = Find-DSSRawObject -LDAPFilter '(objectsid=S-1-5-21-3515480276-2049723633-1306762111-1103)' -OutputFormat 'DirectoryEntry'
        Set-DSSRawObject -Action Remove -Object $FindObject

        Removes (deletes) the object with the above SID.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/new-adobject
        https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.directoryentry
        https://www.petri.com/creating-active-directory-user-accounts-adsi-powershell
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        # The type of AD object to create.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Type,

        # The name of the object.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        # A table of properties to apply to the object.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [HashTable]
        $Properties,

        # An OU path to create the object in.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

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
    $PSBoundParameters.GetEnumerator() | ForEach-Object {
        if ($_.Value -is [hashtable]) {
            $Value = ($_.Value.GetEnumerator() | ForEach-Object { '{0} = {1}' -f $_.Name, $_.Value }) -join ' ; '
        } else {
            $Value = $_.Value -join ' '
        }
        Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, $Value)
    }

    try {
        $Common_Parameters = @('Context', 'Server', 'Credential')
        $Managed_Keys = @('managedby', 'manager')

        $Common_Search_Parameters = @{}
        foreach ($Parameter in $Common_Parameters) {
            if ($PSBoundParameters.ContainsKey($Parameter)) {
                $Common_Search_Parameters[$Parameter] = Get-Variable -Name $Parameter -ValueOnly
            }
        }

        $New_Object_Parameters = @{}
        if ($PSBoundParameters.ContainsKey('Path')) {
            $New_Object_Parameters['SearchBase'] = $Path
        }
        $New_Object_Directory_Entry = Get-DSSDirectoryEntry @Common_Search_Parameters @New_Object_Parameters
        if ($Type -eq 'Group') {
            # Global Security group is the default if no GroupScope or GroupCategory is defined (as per New-ADObject).
            $GroupType_Scope = 2
            $GroupType_Category = -2147483648
        }

        $Post_Creation_Parameters = @{}
        try {
            Write-Verbose ('{0}|Creating "{1}" object with CN={2}' -f $Function_Name, $Type, $Name)
            $New_Object = $New_Object_Directory_Entry.Create($Type, ('CN={0}' -f $Name))
            if ($PSBoundParameters.ContainsKey('Properties')) {
                foreach ($Property in $Properties.GetEnumerator()) {
                    if ($New_Object_Post_Creation_Properties -contains $Property.Name) {
                        Write-Verbose ('{0}|Adding post-creation property "{1}" with value: {2}' -f $Function_Name, $Property.Name, $Property.Value)
                        $Post_Creation_Parameters[$Property.Name] = $Property.Value
                    } elseif ($Managed_Keys -contains $Property.Name) {
                        Write-Verbose ('{0}|Resolving {1} "{2}" to DistinguishedName' -f $Function_Name, $Property.Name, $Property.Value)
                        $Resolved_Key = Get-DSSResolvedObject @Common_Search_Parameters -InputSet $Property.Value
                        Write-Verbose ('{0}|Adding resolved property "{1}" with value: {2}' -f $Function_Name, $Property.Name, $Resolved_Key.'Name')
                        $New_Object.Put($Property.Name, $Resolved_Key.'Name')
                    } elseif ($Property.Name -eq 'GroupCategory') {
                        if ($Property.Value -eq 'Distribution') {
                            Write-Verbose ('{0}|Setting Group Category to: Distribution' -f $Function_Name)
                            $GroupType_Category = 0
                        }
                    } elseif ($Property.Name -eq 'GroupScope') {
                        Write-Verbose ('{0}|Setting Group Scope to: {1}' -f $Function_Name, $Property.Value)
                        $GroupType_Scope = [int]$ADGroupTypes[$Property.Value]
                    } else {
                        Write-Verbose ('{0}|Adding property "{1}" with value: {2}' -f $Function_Name, $Property.Name, $Property.Value)
                        $New_Object.Put($Property.Name, $Property.Value)
                    }
                }
            }
            if ($Type -eq 'Group') {
                $GroupType_Value = $GroupType_Category + $GroupType_Scope
                Write-Verbose ('{0}|Adding property "{1}" with value: {2}' -f $Function_Name, 'grouptype', $GroupType_Value)
                $New_Object.Put('grouptype', $GroupType_Value)
            }
            $New_Object.SetInfo()
            Write-Verbose ('{0}|Object created successfully' -f $Function_Name)
            if ($Post_Creation_Parameters.Count) {
                Write-Verbose ('{0}|Adding post-creation parameters' -f $Function_Name)
                Set-DSSObject -DistinguishedName $New_Object.'distinguishedname' @Common_Search_Parameters @Post_Creation_Parameters
            }

        } catch {
            if ($_.Exception.InnerException.ErrorCode -eq '-2147019886') {
                $Terminating_ErrorRecord_Parameters = @{
                    'Exception'      = 'System.DirectoryServices.ActiveDirectory.ActiveDirectoryOperationException'
                    'ID'             = 'DSS-{0}' -f $Function_Name
                    'Category'       = 'ResourceExists'
                    'TargetObject'   = $New_Object
                    'Message'        = ('The object "{0}" already exists in the path: {1}' -f $Name, $($New_Object_Directory_Entry.'distinguishedname'))
                    'InnerException' = $_.Exception
                }
                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
            } elseif ($_.Exception.InnerException.ErrorCode -eq '-2147016694') {
                # This error is thrown when a property name is invalid or the type is invalid.
                $Terminating_ErrorRecord_Parameters = @{
                    'Exception'      = 'System.DirectoryServices.ActiveDirectory.ActiveDirectoryOperationException'
                    'ID'             = 'DSS-{0}' -f $Function_Name
                    'Category'       = 'InvalidData'
                    'TargetObject'   = $New_Object
                    'Message'        = $_.Exception.Innerexception.Message
                    'InnerException' = $_.Exception
                }
                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
            } elseif ($_.Exception.InnerException.ErrorCode -eq '-2147016651') {
                # This error is thrown when trying to modify a property name that is system owned or otherwise not allowed (eg. objectSID).
                $Terminating_ErrorRecord_Parameters = @{
                    'Exception'      = 'System.DirectoryServices.ActiveDirectory.ActiveDirectoryOperationException'
                    'ID'             = 'DSS-{0}' -f $Function_Name
                    'Category'       = 'InvalidData'
                    'TargetObject'   = $New_Object
                    'Message'        = $_.Exception.Innerexception.Message
                    'InnerException' = $_.Exception
                }
                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
            } else {
                throw $_.Exception.InnerException
            }
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
