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

        # A date and time value that specifies when the account expires.
        # If no time is specified, then the time will be set to 00:00:00 on the supplied date.
        # An example of using this property is:
        #
        # -AccountExpirationDate '25/12/1999'
        # -AccountExpirationDate '25/12/1999 17:30:00'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Object]
        $AccountExpirationDate,

        # Indicates whether the security context of the user is delegated to a service or not.
        # This sets the AccountNotDelegated flag of the UserAccountControl attribute of the user.
        # An example of using this property is:
        #
        # -AccountNotDelegated $true
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $AccountNotDelegated,

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

        # Indicates whether reversible password encryption is allowed for the account.
        # This sets the AllowReversiblePasswordEncryption flag of the UserAccountControl attribute of the user.
        # An example of using this property is:
        #
        # -AllowReversiblePasswordEncryption $true
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $AllowReversiblePasswordEncryption,

        # Specifies whether an account is required to change it's password when next logging on.
        # An example of using this property is:
        #
        # -ChangePasswordAtLogon $true
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $ChangePasswordAtLogon,

        # The value that will be set as the City of the user.
        # An example of using this property is:
        #
        # -City 'San Francisco'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $City,

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

        # The directory context to search - Domain or Forest. By default this will search within the domain only.
        # If you want to search the entire directory, specify "Forest" for this parameter and the search will be performed on a Global Catalog server, targetting the entire forest.
        [Parameter(Mandatory = $false)]
        [ValidateSet('Domain', 'Forest')]
        [String]
        $Context = 'Domain',

        # The credential to use for access to perform the required action.
        # This credential can be provided in the form of a username, DOMAIN\username or as a PowerShell credential object.
        # In the case of a username or DOMAIN\username, you will be prompted to supply the password.
        # Some examples of using this are:
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

        # The value that will be set as the Department of the user.
        # An example of using this property is:
        #
        # -Department 'Engineering'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Department,

        # The value that will be set as the Description of the user.
        # An example of using this property is:
        #
        # -Description 'Joe Smith'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Description,

        # The value that will be set as the DisplayName of the user.
        # An example of using this property is:
        #
        # -DisplayName 'Smith, John'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DisplayName,

        # The value that will be set as the Division of the user.
        # An example of using this property is:
        #
        # -Division 'Marketing'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Division,

        # The value that will be set as the EmailAddress of the user.
        # An example of using this property is:
        #
        # -EmailAddress 'jsmith@contoso.com'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('Mail')]
        [String]
        $EmailAddress,

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

        # Specifies whether an account is enabled.
        # This sets the Enabled flag of the UserAccountControl attribute of the user.
        # An example of using this property is:
        #
        # -Enabled $false
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $Enabled,

        # The value that will be set as the Fax number of the user.
        # An example of using this property is:
        #
        # -Fax '000-1111 2222'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('FacsimileTelephoneNumber')]
        [String]
        $Fax,

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

        # The value that will be set as the HomePage of the user.
        # An example of using this property is:
        #
        # -HomePage 'intranet.contoso.com/jsmith'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('WWWHomePage')]
        [String]
        $HomePage,

        # The value that will be set as the HomePhone of the user.
        # An example of using this property is:
        #
        # -HomePhone '000-000-1111'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $HomePhone,

        # The value that will be set as the Middle Initial(s) of the user.
        # An example of using this property is:
        #
        # -Initials 'AJ'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Initials,

        # The value that will be set as the MobilePhone of the user.
        # An example of using this property is:
        #
        # -MobilePhone '0000 111 1111'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('Mobile')]
        [String]
        $MobilePhone,

        # The value that will be set as the Office of the user.
        # An example of using this property is:
        #
        # -Office 'San Francisco'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('PhysicalDeliveryOfficeName')]
        [String]
        $Office,

        # The value that will be set as the OfficePhone of the user.
        # An example of using this property is:
        #
        # -OfficePhone '(000) 000 1111'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $OfficePhone,

        # The value that will be set as the Organization of the user.
        # An example of using this property is:
        #
        # -Organization 'Contoso'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Organization,

        # The value that will be set as the OtherName of the user. This sets the LDAP property middleName, which is what this property is used for.
        # An example of using this property is:
        #
        # -OtherName 'Richard'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('MiddleName')]
        [String]
        $OtherName,

        # Specifies that the account password does not expire.
        # This sets the PasswordNeverExpires flag of the UserAccountControl attribute of the user.
        # An example of using this property is:
        #
        # -PasswordNeverExpires $true
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $PasswordNeverExpires,

        # Specifies whether the user account requires a password.
        # This sets the PasswordNotRequired flag of the UserAccountControl attribute of the user.
        # An example of using this property is:
        #
        # -PasswordNotRequired $true
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $PasswordNotRequired,

        # The value that will be set as the POBox of the user.
        # An example of using this property is:
        #
        # -POBox '111'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('PostOfficeBox')]
        [String]
        $POBox,

        # The value that will be set as the PostalCode of the user.
        # An example of using this property is:
        #
        # -PostalCode '12345'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $PostalCode,

        # The value that will be set as the ProfilePath of the user. This should be a local path or a UNC path with with a server and share specified.
        # An example of using this property is:
        #
        # -ProfilePath 'D:\Profiles\JSmith'
        # -ProfilePath '\\fileserver01\profiles$\jsmith'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ProfilePath,

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

        # The value that will be set as the ScriptPath of the user. This is the value of the user's log on script.
        # This should be a local path to a file or a UNC path with with a server, share and file path specified.
        # An example of using this property is:
        #
        # -ScriptPath 'D:\Scripts\logon.bat'
        # -ScriptPath '\\dc01.contoso.com\netlogon\logon.bat'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptPath,

        # The server or domain to connect to.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Server,

        # Specifies whether the user requires a smart card for logon.
        # This sets the SmartcardLogonRequired flag of the UserAccountControl attribute of the user.
        # An example of using this property is:
        #
        # -SmartcardLogonRequired $true
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $SmartcardLogonRequired,

        # The value that will be set as the State of the user.
        # An example of using this property is:
        #
        # -State 'California'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('St')]
        [String]
        $State,

        # The value that will be set as the StreetAddress of the user.
        # To add a value that displays as multiple lines in any output, separate each line with a carriage return and newline (`r`n).
        # Note that the characters before the "r" and "n" are backticks (grave accents) and not regular quotes (apostrophes).
        # Additionally, in order for PowerShell to parse the carriage return and newline, the string needs to be within double quotes and not single quotes.
        # Some examples of using this property are:
        #
        # -StreetAddress '1 Main St'
        # -StreetAddress "First Line`r`nSecond Line"
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $StreetAddress,

        # The value that will be set as the Surname of the user.
        # An example of using this property is:
        #
        # -Surname 'Smith'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('LastName', 'Sn')]
        [String]
        $Surname,

        # The value that will be set as the Title of the user. This is the value that appears as "Job Title" in the GUI.
        # An example of using this property is:
        #
        # -Title 'Manager'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('JobTitle')]
        [String]
        $Title,

        # Specifies whether an account is trusted for Kerberos delegation.
        # This sets the TrustedForDelegation flag of the UserAccountControl attribute of the user.
        # An example of using this property is:
        #
        # -TrustedForDelegation $true
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $TrustedForDelegation,

        # The value that will be set as the UserPrincipalName of the user.
        # An example of using this property is:
        #
        # -UserPrincipalName 'jsmith@contoso.com'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('UPN')]
        [String]
        $UserPrincipalName
    )

    # parameters to add:
    # ------------------
    # AuthenticationPolicy
    # AuthenticationPolicySilo
    # AuthType
    # CannotChangePassword
    # Certificates
    # CompoundIdentitySupported
    # Country
    # Instance
    # KerberosEncryptionType
    # LogonWorkstations
    # Manager
    # Partition
    # PassThru
    # PrincipalsAllowedToDelegateToAccount
    # ServicePrincipalNames

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    try {
        $Common_Parameters = @('Context', 'Server', 'Credential')
        $Common_Search_Parameters = @{ }
        foreach ($Parameter in $Common_Parameters) {
            if ($PSBoundParameters.ContainsKey($Parameter)) {
                $Common_Search_Parameters[$Parameter] = Get-Variable -Name $Parameter -ValueOnly
                [void]$PSBoundParameters.Remove($Parameter)
            }
        }

        $Default_LDAPFilter = '(objectclass=user)'
        $Identity_Parameters = @('SAMAccountName', 'DistinguishedName', 'ObjectSID', 'ObjectGUID')
        foreach ($Parameter in $Identity_Parameters) {
            if ($PSBoundParameters.ContainsKey($Parameter)) {
                $Directory_Search_Type = $Parameter
                $Directory_Search_Value = Get-Variable -Name $Parameter -ValueOnly
                $LDAPFilter = '(&{0}({1}={2}))' -f $Default_LDAPFilter, $Directory_Search_Type, $Directory_Search_Value
                [void]$PSBoundParameters.Remove($Parameter)
            }
        }
        $Directory_Search_Parameters = @{
            'LDAPFilter'   = $LDAPFilter
            'OutputFormat' = 'DirectoryEntry'
        }

        $Object_Directory_Entry = Find-DSSRawObject @Common_Search_Parameters @Directory_Search_Parameters
        if ($Object_Directory_Entry) {
            $Set_Parameters = Confirm-DSSObjectParameters -BoundParameters $PSBoundParameters

            if ($Set_Parameters.Count) {
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
                'Message'      = 'Cannot find {0} with {1} of "{2}"' -f ($Function_Name -replace '[GS]et-DSS'), $Directory_Search_Type, $Directory_Search_Value
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
