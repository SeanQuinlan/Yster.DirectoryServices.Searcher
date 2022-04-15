function New-DSSRawObject {
    <#
    .SYNOPSIS
        Creates a new object in Active Directory.
    .DESCRIPTION
        Creates a new Active Directory object of the type specified and sets any additional properties that are supplied.

        This is not meant to be used as an interactive function; it is used as a worker function by many of the other higher-level functions.
    .EXAMPLE
        New-DSSRawObject -Type 'computer' -Name 'WINSRV01' -Path 'OU=Computers,OU=Company,DC=contoso,DC=com'

        Creates the above computer object in the specified OU.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/new-adobject
        https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.directoryentry
        https://www.petri.com/creating-active-directory-user-accounts-adsi-powershell
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
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

        # The name of the object.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        # An OU path to create the object in.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        # A table of properties to apply to the object.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('Property')]
        [Hashtable]
        $Properties,

        # The server to connect to.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Server,

        # The type of AD object to create.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Type
    )

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object {
        if ($_.Value -is [Hashtable]) {
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
        } else {
            switch -Regex ($Type) {
                'Computer' {
                    $New_Object_Parameters['SearchBase'] = (Get-DSSDomain @Common_Search_Parameters -Properties 'computerscontainer').'computerscontainer'
                }
                'User|iNetOrgPerson' {
                    $New_Object_Parameters['SearchBase'] = (Get-DSSDomain @Common_Search_Parameters -Properties 'userscontainer').'userscontainer'
                }
            }
        }
        $New_Object_Directory_Entry = Get-DSSDirectoryEntry @Common_Search_Parameters @New_Object_Parameters
        if ($Type -eq 'Group') {
            # Global Security group is the default if no GroupScope or GroupCategory is defined (as per New-ADObject).
            $GroupType_Scope = 2
            $GroupType_Category = -2147483648
        }

        # Some defaults for certain types of accounts. These match the same accounts created by the Microsoft New-ADXXX cmdlets.
        # - https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
        switch -Regex ($Type) {
            'Computer' {
                # 0x1000 = WORKSTATION_TRUST_ACCOUNT
                $Default_UserAccountControl = 0x1000
            }
            'User|iNetOrgPerson' {
                # 0x200 = NORMAL_ACCOUNT
                # 0x002 = ACCOUNTDISABLE
                $Default_UserAccountControl = 0x202
            }
        }

        $Post_Creation_Parameters = @{}
        try {
            if ($Type -eq 'OrganizationalUnit') {
                $Object_Name = 'OU={0}' -f $Name
            } else {
                $Object_Name = 'CN={0}' -f $Name
            }
            Write-Verbose ('{0}|Creating "{1}" object with {2}' -f $Function_Name, $Type, $Object_Name)
            $New_Object = $New_Object_Directory_Entry.Create($Type, $Object_Name)
            if ($Default_UserAccountControl) {
                Write-Verbose ('{0}|Setting default UserAccountControl for type "{1}" to: {2}' -f $Function_Name, $Type, $Default_UserAccountControl)
                $New_Object.Put('useraccountcontrol', $Default_UserAccountControl)
            }
            if ($PSBoundParameters.ContainsKey('Properties')) {
                foreach ($Property in $Properties.GetEnumerator()) {
                    if ($New_Object_Post_Creation_Properties -contains $Property.Name) {
                        Write-Verbose ('{0}|Adding post-creation property "{1}" with value: {2}' -f $Function_Name, $Property.Name, $Property.Value)
                        $Post_Creation_Parameters[$Property.Name] = $Property.Value
                    } elseif ($Managed_Keys -contains $Property.Name) {
                        Write-Verbose ('{0}|Resolving {1} "{2}" to DistinguishedName' -f $Function_Name, $Property.Name, $Property.Value)
                        $Resolved_Key = Get-DSSResolvedObject @Common_Search_Parameters -InputSet $Property.Value
                        Write-Verbose ('{0}|Adding resolved property "{1}" with value: {2}' -f $Function_Name, $Property.Name, $Resolved_Key.'distinguishedname')
                        $New_Object.Put($Property.Name, $Resolved_Key.'distinguishedname')
                    } elseif ($Property.Name -eq 'GroupCategory') {
                        if ($Property.Value -eq 'Distribution') {
                            Write-Verbose ('{0}|Setting Group Category to: Distribution' -f $Function_Name)
                            $GroupType_Category = 0
                        }
                    } elseif ($Property.Name -eq 'GroupScope') {
                        Write-Verbose ('{0}|Setting Group Scope to: {1}' -f $Function_Name, $Property.Value)
                        $GroupType_Scope = [int]$ADGroupTypes[$Property.Value]
                    } elseif ($Property.Name -eq 'AccountExpirationDate') {
                        Write-Verbose ('{0}|Converting DateTime to int64' -f $Function_Name)
                        $Account_Expires_Int64 = (Get-Date $Property.Value).ToFileTime()
                        $New_Object.Put('accountexpires', $Account_Expires_Int64.ToString()) # Value has to be a string for some reason.
                    } elseif ($Property.Name -eq 'AccountPassword') {
                        $Set_Account_Password = $true
                        $Account_Passsword = $Property.Value
                    } elseif (($Property.Name -eq 'Enabled') -and ($Property.Value -eq $true)) {
                        $Set_Account_Enabled = $true
                    } elseif ($Property.Name -eq 'c') {
                        $Country_Property = $Property.Value
                        if (($Countries_Ambiguous_Alpha2 -contains $Country_Property) -or ($Countries_Ambiguous_CountryCodes -contains $Country_Property)) {
                            $Terminating_ErrorRecord_Parameters = @{
                                'Exception'    = 'System.ArgumentException'
                                'ID'           = 'DSS-{0}' -f $Function_Name
                                'Category'     = 'InvalidData'
                                'TargetObject' = $Object
                                'Message'      = 'The specified country code "{0}" can apply to multiple country names. Please supply full country name instead.' -f $Country_Property
                            }
                            $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                        } elseif (($Countries_Fullnames -notcontains $Country_Property) -and ($Countries_Alpha2 -notcontains $Country_Property) -and ($Countries_CountryCodes -notcontains $Country_Property)) {
                            $Terminating_ErrorRecord_Parameters = @{
                                'Exception'    = 'System.ArgumentException'
                                'ID'           = 'DSS-{0}' -f $Function_Name
                                'Category'     = 'InvalidData'
                                'TargetObject' = $Object
                                'Message'      = 'The specified country "{0}" cannot be matched to a full country name or country code.' -f $Country_Property
                            }
                            $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                        } else {
                            if ($Countries_Fullnames -contains $Country_Property) {
                                $Country_FullName = $Property
                            } elseif ($Countries_Alpha2 -contains $Country_Property) {
                                $Country_FullName = ($Countries.GetEnumerator() | Where-Object { $_.Value.'Alpha2' -eq $Country_Property }).Name
                            } elseif ($Countries_CountryCodes -contains $Country_Property) {
                                $Country_FullName = ($Countries.GetEnumerator() | Where-Object { $_.Value.'CountryCode' -eq $Country_Property }).Name
                            }

                            $New_Object.Put('co', $Country_FullName)
                            $New_Object.Put('c', $Countries[$Country_FullName]['Alpha2'])
                            $New_Object.Put('countrycode', $Countries[$Country_FullName]['CountryCode'])
                        }
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
            Write-Verbose ('{0}|Creating object in AD...' -f $Function_Name)
            $New_Object.SetInfo()
            Write-Verbose ('{0}|Object created successfully' -f $Function_Name)
            if ($Post_Creation_Parameters.Count) {
                Write-Verbose ('{0}|Adding post-creation parameters' -f $Function_Name)
                Set-DSSObject -DistinguishedName $New_Object.'distinguishedname' @Common_Search_Parameters @Post_Creation_Parameters
                $New_Object.RefreshCache()
            }
            if ($Set_Account_Password) {
                Write-Verbose ('{0}|Setting password' -f $Function_Name)
                $Account_Password_Text = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Account_Passsword))
                $New_Object.SetPassword($Account_Password_Text)
                $New_Object.SetInfo()
            }
            # Need to wait until the password has been set before enabling an account.
            if ($Set_Account_Enabled) {
                Write-Verbose ('{0}|Enabling account' -f $Function_Name)
                Set-DSSObject -DistinguishedName $New_Object.'distinguishedname' @Common_Search_Parameters -Enabled $true
            }

        } catch {
            if ($_.Exception.InnerException.ErrorCode -eq '-2147019886') {
                $Terminating_ErrorRecord_Parameters = @{
                    'Exception'      = 'System.DirectoryServices.ActiveDirectory.ActiveDirectoryOperationException'
                    'ID'             = 'DSS-{0}' -f $Function_Name
                    'Category'       = 'ResourceExists'
                    'TargetObject'   = $New_Object
                    'Message'        = 'The object "{0}" already exists in the path: {1}' -f $Name, $($New_Object_Directory_Entry.'distinguishedname')
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
                    'Message'        = "Property name or type is invalid.`nServer Error: {0}" -f $_.Exception.InnerException.Message
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
                    'Message'        = "Unable to modify a property that is system owned or otherwise not allowed.`nServer Error: {0}" -f $_.Exception.InnerException.Message
                    'InnerException' = $_.Exception
                }
                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
            } elseif ($_.Exception.InnerException.ErrorCode -eq '-2147016684') {
                # This error is thrown when trying to add a property that is not available for that class of object.
                $Terminating_ErrorRecord_Parameters = @{
                    'Exception'      = 'System.DirectoryServices.ActiveDirectory.ActiveDirectoryOperationException'
                    'ID'             = 'DSS-{0}' -f $Function_Name
                    'Category'       = 'InvalidData'
                    'TargetObject'   = $New_Object
                    'Message'        = "One or more of the OtherAttributes is not valid for this type of object.`nServer Error: {0}" -f $_.Exception.InnerException.Message
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
