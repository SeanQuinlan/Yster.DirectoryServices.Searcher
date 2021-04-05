function New-DSSUser {
    <#
    .SYNOPSIS
        Creates a new user account in Active Directory.
    .DESCRIPTION
        Creates a user account in Active Directory, using the properties supplied.
    .EXAMPLE
        New-DSSComputer -Name 'WIN-SRV01' -Path 'OU=Computers,OU=Company,DC=contoso,DC=com'

        Creates the computer object in the specified OU path.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/new-aduser
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        # A date and time value that specifies when the account expires.
        # If no time is specified, then the time will be set to 00:00:00 on the supplied date.
        # Some examples of using this property are:
        #
        # -AccountExpirationDate '25/12/1999'
        # -AccountExpirationDate '25/12/1999 17:30:00'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Object]
        $AccountExpirationDate,

        # Indicates whether the security context of the object is delegated to a service or not.
        # This sets the AccountNotDelegated flag of the UserAccountControl attribute.
        # An example of using this property is:
        #
        # -AccountNotDelegated $true
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $AccountNotDelegated,

        # The value to set as the account password for the object.
        # An example of using this property is:
        #
        # $AccPass = ConvertTo-SecureString -String 'P@ssw0rd' -AsPlainText -Force
        # -AccountPassword $AccPass
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $AccountPassword,

        # Indicates whether reversible password encryption is allowed for the account.
        # This sets the AllowReversiblePasswordEncryption flag of the UserAccountControl attribute of the account.
        # An example of using this property is:
        #
        # -AllowReversiblePasswordEncryption $true
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $AllowReversiblePasswordEncryption,

        # Specifies whether an account's password can be changed.
        # An example of using this property is:
        #
        # -CannotChangePassword $true
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $CannotChangePassword,

        # A list of Certificates to add to the object.
        # These certificates must be of type: System.Security.Cryptography.X509Certificates.X509Certificate
        # See below for some examples:
        #
        # -Certificates $cert1
        # -Certificates $cert1, $cert2
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Array]
        $Certificates,

        # Specifies whether an account is required to change it's password when next logging on.
        # An example of using this property is:
        #
        # -ChangePasswordAtLogon $true
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $ChangePasswordAtLogon,

        # The value that will be set as the City of the organizational unit.
        # An example of using this property is:
        #
        # -City 'San Francisco'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $City,

        # The value that will be set as the Company of the object.
        # An example of using this property is:
        #
        # -Company 'Contoso, Inc'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Company,

        # Indicates whether an account supports Kerberos service tickets which includes the authorization data for the user's device.
        # An example of using this property is:
        #
        # -CompoundIdentitySupported $true
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $CompoundIdentitySupported,

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

        # The value that will be set as the Country of the object. This sets 3 properties at once: co, country and countrycode.
        # This property can be set using the long country name, the short 2-letter country code or the numerical countrycode.
        # The long country name must exactly match the name as seen in the Active Directory Users and Computers property panel.
        # Some examples of using this property are:
        #
        # -Country 'United Kingdom'
        # -Country 'gb'
        # -Country 826
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('CountryCode')]
        [String]
        $Country,

        # The value that will be set as the Department of the object.
        # An example of using this property is:
        #
        # -Department 'Engineering'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Department,

        # The value that will be set as the Description of the object.
        # An example of using this property is:
        #
        # -Description 'Sales Manager'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Description,

        # The value that will be set as the DisplayName of the object.
        # An example of using this property is:
        #
        # -DisplayName 'Smith, John'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DisplayName,

        # The value that will be set as the Division of the object.
        # An example of using this property is:
        #
        # -Division 'Marketing'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Division,

        # The value that will be set as the EmailAddress of the object.
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

        # Specifies whether an object is enabled.
        # This sets the Enabled flag of the UserAccountControl attribute of the object.
        # An example of using this property is:
        #
        # -Enabled $false
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $Enabled,

        # The value that will be set as the Fax number of the object.
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
        # Some examples of using this property are:
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

        # The value that will be set as the HomePage of the object.
        # An example of using this property is:
        #
        # -HomePage 'intranet.contoso.com/sales'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('WWWHomePage')]
        [String]
        $HomePage,

        # The value that will be set as the Middle Initial(s) of the user.
        # An example of using this property is:
        #
        # -Initials 'AJ'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Initials,

        # The Kerberos Encryption Types supported by the account. Must be one or more of the following: DES, RC4, AES128, AES256 or None.
        # Setting this value to "None" will remove the other encryption types.
        # Some examples of using this property are:
        #
        # -KerberosEncryptionType None
        # -KerberosEncryptionType 'AES128','AES256'
        [Parameter(Mandatory = $false)]
        [ValidateSet(
            'None',
            'DES',
            'RC4',
            'AES128',
            'AES256'
        )]
        [String[]]
        $KerberosEncryptionType,

        # Specifies the computers that the user can log onto. More than one computer can be specified by supplying a string with the names separated by commas.
        # Some examples of using this property are:
        #
        # -LogonWorkstations "WS001"
        # -LogonWorkstations "WS001,WS002,WS003"
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $LogonWorkstations,

        # Sets the Manager property of the user. This value can be one of the following object types:
        # ..DistinguishedName
        # ..ObjectSID (SID)
        # ..ObjectGUID (GUID)
        # ..SAMAccountName
        #
        # Some examples of using this property are:
        #
        # -Manager 'rsmith'
        # -Manager 'CN=rsmith,OU=Users,OU=Company,DC=contoso,DC=com'
        # -Manager 'S-1-5-21-3387319312-2301824641-2614994224-7110'
        # -Manager 'f4fcc8dc-bd82-41d0-bc0a-5c44350bbb62'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Manager,

        # The value that will be set as the MobilePhone of the user.
        # An example of using this property is:
        #
        # -MobilePhone '0000 111 1111'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('Mobile')]
        [String]
        $MobilePhone,

        # The name of the object to create. This will be the CN attribute for the object.
        # An example of using this property is:
        #
        # -Name 'rsmith'
        [Parameter(Mandatory = $true, Position = 0)]
        [String]
        $Name,

        # The value that will be set as the Office of the object.
        # An example of using this property is:
        #
        # -Office 'San Francisco'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('PhysicalDeliveryOfficeName')]
        [String]
        $Office,

        # The value that will be set as the OfficePhone of the object.
        # An example of using this property is:
        #
        # -OfficePhone '(000) 000 1111'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $OfficePhone,

        # The value that will be set as the Organization of the object.
        # An example of using this property is:
        #
        # -Organization 'Contoso'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Organization,

        # A hashtable of attributes/properties and values to set on the object.
        # Multiple values for the same property can be separated by commas.
        # Multiple properties can also be specified by separating them with semi-colons.
        # See below for some examples:
        #
        # -OtherAttributes @{description='Senior Manager'}
        # -OtherAttributes @{otherTelephone='000-0000-0000','111-1111-1111'}
        # -OtherAttributes @{givenname='John'; sn='Smith'; displayname='Smith, John'}
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $OtherAttributes,

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
        # This sets the PasswordNeverExpires flag of the UserAccountControl attribute of the account.
        # An example of using this property is:
        #
        # -PasswordNeverExpires $true
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $PasswordNeverExpires,

        # Specifies whether the account requires a password.
        # This sets the PasswordNotRequired flag of the UserAccountControl attribute.
        # An example of using this property is:
        #
        # -PasswordNotRequired $true
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $PasswordNotRequired,

        # An OU path to create the object in.
        # An example of using this property is:
        #
        # -Path = 'OU=Users,OU=Company,DC=contoso,DC=com'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        # The value that will be set as the POBox of the object.
        # An example of using this property is:
        #
        # -POBox '111'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('PostOfficeBox')]
        [String]
        $POBox,

        # The value that will be set as the PostalCode of the object.
        # An example of using this property is:
        #
        # -PostalCode '12345'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $PostalCode,

        # A list of PrincipalsAllowedToDelegateToAccount for the object.
        # The VALUE references an AD object, and can be supplied in one of the following forms:
        # ..DistinguishedName
        # ..ObjectSID (SID)
        # ..ObjectGUID (GUID)
        # ..SAMAccountName
        #
        # See below for some examples:
        #
        # -PrincipalsAllowedToDelegateToAccount 'svc_SQL'
        # -PrincipalsAllowedToDelegateToAccount '0911f77e-862a-4bd7-a073-282289ad51ab', 'S-1-5-21-739503189-1020924195-124678973-1172'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Array]
        $PrincipalsAllowedToDelegateToAccount,

        # The value that will be set as the ProfilePath of the user. This should be a local path or a UNC path with with a server and share specified.
        # Some examples of using this property are:
        #
        # -ProfilePath 'D:\Profiles\JSmith'
        # -ProfilePath '\\fileserver01\profiles$\jsmith'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ProfilePath,

        # The value to set for the SAMAccountName.
        # By default, this is set to the same as the Name field, with a "$" appended, eg. COMP001$ for the Name "COMP001"
        #
        # An example of using this property is:
        #
        # -SAMAccountName 'rsmith'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $SAMAccountName,

        # The value that will be set as the ScriptPath of the user. This is the value of the user's log on script.
        # This should be a local path to a file or a UNC path with with a server, share and file path specified.
        # Some examples of using this property are:
        #
        # -ScriptPath 'D:\Scripts\logon.bat'
        # -ScriptPath '\\dc01.contoso.com\netlogon\logon.bat'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptPath,

        # The server or domain to connect to.
        # See below for some examples:
        #
        # -Server DC01
        # -Server 'dc01.contoso.com'
        # -Server CONTOSO
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Server,

        # A list of ServicePrincipalNames for the object.
        # See below for some examples:
        #
        # -ServicePrincipalNames 'HTTP/SERVER01'
        # -ServicePrincipalNames 'HTTP/SERVER01','HTTP/SERVER01.contoso.com'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('ServicePrincipalName')]
        [Array]
        $ServicePrincipalNames,

        # Specifies whether the account requires a smart card for logon.
        # This sets the SmartcardLogonRequired flag of the UserAccountControl attribute of the account.
        # An example of using this property is:
        #
        # -SmartcardLogonRequired $true
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $SmartcardLogonRequired,

        # The value that will be set as the State of the object.
        # An example of using this property is:
        #
        # -State 'California'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('St')]
        [String]
        $State,

        # The value that will be set as the StreetAddress of the object.
        # To add a value that displays as multiple lines in any output, separate each line with a carriage return and newline (`r`n).
        # Note that the characters before the "r" and "n" are backticks (grave accents) and not regular quotes/apostrophes.
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
        # This sets the TrustedForDelegation flag of the UserAccountControl attribute.
        # An example of using this property is:
        #
        # -TrustedForDelegation $true
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $TrustedForDelegation,

        # The type of user object to create. The type must be a subclass of the User schema class.
        # An example of using this property is:
        #
        # -Type 'iNetOrgPerson'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Type = 'User',

        # The value that will be set as the UserPrincipalName of the object.
        # An example of using this property is:
        #
        # -UserPrincipalName 'rsmith@contoso.com'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('UPN')]
        [String]
        $UserPrincipalName
    )

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    try {
        $Convert_To_Hashtable_Parameters = @('Certificates', 'PrincipalsAllowedToDelegateToAccount', 'ServicePrincipalNames')
        $Convert_To_Hashtable_Parameters | ForEach-Object {
            if ($PSBoundParameters.ContainsKey($_)) {
                $Parameter_New_Value = @{'Replace' = $PSBoundParameters[$_] }
                [void]$PSBoundParameters.Remove($_)
                [void]$PSBoundParameters.Add($_, $Parameter_New_Value)
            }
        }
        if ($PSBoundParameters.ContainsKey('Type')) {
            Write-Verbose ('{0}|Getting Schema Naming Context' -f $Function_Name)
            $Schema_Naming_Context = (Get-DSSRootDSE).schemaNamingContext
            $User_Category_Search_Parameters = @{
                'SearchBase'          = $Schema_Naming_Context
                'LDAPFilter'          = '(ldapdisplayname=user)'
                'Properties'          = 'defaultobjectcategory'
                'NoDefaultProperties' = $true
            }
            Write-Verbose ('{0}|Getting Default Object Category for Users' -f $Function_Name)
            $User_Category = (Find-DSSObject @User_Category_Search_Parameters).'defaultobjectcategory'

            $User_SubClass_Search_Parameters = @{
                'SearchBase'          = $Schema_Naming_Context
                'LDAPFilter'          = '(&(|(subclassof=user)(ldapdisplayname=user))(defaultobjectcategory={0}))' -f $User_Category
                'Properties'          = 'name'
                'NoDefaultProperties' = $true
            }
            $User_SubClass_Names = (Find-DSSObject @User_SubClass_Search_Parameters).'name'
            if ($User_SubClass_Names -notcontains $Type) {
                $Terminating_ErrorRecord_Parameters = @{
                    'Exception'    = 'System.ArgumentException'
                    'ID'           = 'DSS-{0}' -f $Function_Name
                    'Category'     = 'InvalidArgument'
                    'TargetObject' = $Type
                    'Message'      = 'The specified ObjectClass is not valid for this object type: {0}' -f $Type
                }
                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
            }
            [void]$PSBoundParameters.Remove('Type')
        }
        if (-not $PSBoundParameters.ContainsKey('SAMAccountName')) {
            $PSBoundParameters['SAMAccountName'] = $Name
        }
        Write-Verbose ('{0}|Calling New-DSSObjectWrapper' -f $Function_Name)
        New-DSSObjectWrapper -ObjectType $Type -BoundParameters $PSBoundParameters

    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}
