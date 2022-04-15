function Set-DSSUser {
    <#
    .SYNOPSIS
        Modifies an LDAP attribute of a User object from Active Directory.
    .DESCRIPTION
        Queries Active Directory for a specific user object and then modifies one or more attributes on this object.
        The object can be specified using one of the following
            - DistinguishedName
            - ObjectGUID (GUID)
            - ObjectSID (SID)
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
        # A date and time value that specifies when the account expires.
        # If no time is specified, then the time will be set to 00:00:00 on the supplied date.
        # Some examples of using this property are:
        #
        # -AccountExpirationDate '25/12/1999'
        # -AccountExpirationDate '25/12/1999 17:30:00'
        # -AccountExpirationDate (Get-Date).AddDays(90)
        #
        # The AccountExpirationDate can be cleared with the following:
        # -AccountExpirationDate $null
        [Parameter(Mandatory = $false)]
        [AllowNull()]
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
        [Hashtable]
        $Add,

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

        # A hashtable that defines the Certificate(s) to add, remove or replace on the object.
        # Add and remove will add or remove individual entries (if found). Replace will replace all entries with just those specified.
        # The hashtable KEY has to be add, remove or replace.
        # The corresponding hashtable VALUE has to be an object (or an array) of type: System.Security.Cryptography.X509Certificates.X509Certificate
        #
        # See below for some examples:
        #
        # $TemplateCert = (Get-DSSUser -DistinguishedName 'CN=TemplateUser,CN=Users,DC=contoso,DC=com' -Properties Certificates).Certificates
        # Set-DSSUser -SAMAccountName rsmith -Certificates @{Replace=$TemplateCert}
        #
        # All user certificates on the rsmith account will be replaced with the certificates from the TemplateUser account.
        #
        # $BadCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate
        # $BadCert.Import("badcert.cer")
        # Set-DSSUser -DistinguishedName 'CN=TemplateUser,CN=Users,DC=contoso,DC=com' -Certificates @{Remove = $BadCert}
        #
        # Imports a certificate from a local file and removes that certificate from the TemplateUser's published certificates.
        #
        # Multiple actions can also be specified by providing multiple lines within the hashtable. For example:
        # -Certificates @{Remove=$cert1; Add=$cert2}
        #
        # Multiple certificates can be specified per action, by separating them with a comma. For example:
        # -Certificates @{Add=$cert1,$cert2}
        #
        # You can clear all entries with this:
        # -Certificates $null
        #
        # If specifying the Add, Remove and Replace parameters together, they are processed in this order:
        # ..Remove
        # ..Add
        # ..Replace
        [Parameter(Mandatory = $false)]
        [Hashtable]
        $Certificates,

        # Specifies whether an account is required to change it's password when next logging on.
        # An example of using this property is:
        #
        # -ChangePasswordAtLogon $true
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $ChangePasswordAtLogon,

        # The value that will be set as the City of the object.
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
        # -Description 'Joe Smith'
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

        # The DistinguishedName of the user.
        [Parameter(Mandatory = $true, ParameterSetName = 'DistinguishedName')]
        [ValidateNotNullOrEmpty()]
        [Alias('DN')]
        [String]
        $DistinguishedName,

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
        # -HomePage 'intranet.contoso.com/jsmith'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('WWWHomePage')]
        [String]
        $HomePage,

        # The value that will be set as the HomePhone of the object.
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

        # The ObjectGUID of the user.
        [Parameter(Mandatory = $true, ParameterSetName = 'GUID')]
        [ValidateNotNullOrEmpty()]
        [Alias('GUID')]
        [String]
        $ObjectGUID,

        # The ObjectSID of the user.
        [Parameter(Mandatory = $true, ParameterSetName = 'SID')]
        [ValidateNotNullOrEmpty()]
        [Alias('SID')]
        [String]
        $ObjectSID,

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

        # Specifies whether the account requires a password.
        # This sets the PasswordNotRequired flag of the UserAccountControl attribute.
        # An example of using this property is:
        #
        # -PasswordNotRequired $true
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $PasswordNotRequired,

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

        # A hashtable that defines the PrincipalsAllowedToDelegateToAccount to add, remove or replace on the object.
        # Add and remove will add or remove individual entries (if found). Replace will replace all entries with just those specified.
        # The hashtable KEY has to be add, remove or replace.
        # The corresponding hashtable VALUE can be a single string or multiple strings (separated by commas).
        # The VALUE references a user object, and can be supplied in one of the following forms:
        # ..DistinguishedName
        # ..ObjectSID (SID)
        # ..ObjectGUID (GUID)
        # ..SAMAccountName
        #
        # See below for some examples:
        # -PrincipalsAllowedToDelegateToAccount @{Add='SVC_Acc'}
        # -PrincipalsAllowedToDelegateToAccount @{Add='0911f77e-862a-4bd7-a073-282289ad51ab','S-1-5-21-739503189-1020924195-124678973-1172'}
        # -PrincipalsAllowedToDelegateToAccount @{Remove='0911f77e-862a-4bd7-a073-282289ad51ab'}
        # -PrincipalsAllowedToDelegateToAccount @{Replace='S-1-5-21-739503189-1020924195-124678973-1172','rsmith'}
        #
        # Multiple actions can also be specified by providing multiple lines within the hashtable. For example:
        # -PrincipalsAllowedToDelegateToAccount @{Remove='0911f77e-862a-4bd7-a073-282289ad51ab'; Add='S-1-5-21-739503189-1020924195-124678973-1172'}
        #
        # You can clear all entries with this:
        # -PrincipalsAllowedToDelegateToAccount $null
        #
        # If specifying the Add, Remove and Replace parameters together, they are processed in this order:
        # ..Remove
        # ..Add
        # ..Replace
        [Parameter(Mandatory = $false)]
        [Hashtable]
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

        # Specifies whether the object is protected from accidental deletion.
        # An example of using this property is:
        #
        # -ProtectedFromAccidentalDeletion $false
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $ProtectedFromAccidentalDeletion,

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
        [Hashtable]
        $Remove,

        # A property name and a value or set of values that will be used to replace the existing property values.
        # Multiple values for the same property can be separated by commas.
        # Multiple properties can also be specified by separating them with semi-colons.
        # See below for some examples:
        #
        # -Replace @{description='Senior Manager'}
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
        [Hashtable]
        $Replace,

        # The SAMAccountName of the user.
        [Parameter(Mandatory = $true, ParameterSetName = 'SAM')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript(
            {
                if ($_ -match '[\*\?]') {
                    throw [System.Management.Automation.ValidationMetadataException] 'Cannot contain wildcards'
                } else {
                    $true
                }
            }
        )]
        [Alias('SAM')]
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

        # A hashtable that defines the ServicePrincipalNames to add, remove or replace on the object.
        # Add and remove will add or remove individual entries (if found). Replace will replace all entries with just those specified.
        # The hashtable KEY has to be add, remove or replace.
        # The corresponding hashtable VALUE can be a single string or multiple strings (separated by commas).
        #
        # See below for some examples:
        # -ServicePrincipalNames @{Add='MSSQLSvc/SQLServer01.contoso.com'}
        # -ServicePrincipalNames @{Add='MSSQLSvc/SQLServer01','MSSQLSvc/SQLServer01.contoso.com'}
        # -ServicePrincipalNames @{Remove='MSSQLSvc/SQLServer01'}
        # -ServicePrincipalNames @{Replace='MSSQLSvc/SQLServer02','MSSQLSvc/SQLServer02.contoso.com'}
        #
        # Multiple actions can also be specified by providing multiple lines within the hashtable. For example:
        # -ServicePrincipalNames @{Remove='MSSQLSvc/SQLServer01'; Add='MSSQLSvc/SQLServer02'}
        #
        # You can clear all entries with this:
        # -ServicePrincipalNames $null
        #
        # If specifying the Add, Remove and Replace parameters together, they are processed in this order:
        # ..Remove
        # ..Add
        # ..Replace
        [Parameter(Mandatory = $false)]
        [Alias('ServicePrincipalName')]
        [Hashtable]
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

        # The value that will be set as the UserPrincipalName of the account.
        # An example of using this property is:
        #
        # -UserPrincipalName 'jsmith@contoso.com'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('UPN')]
        [String]
        $UserPrincipalName
    )

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    try {
        $Null_Equal_Clear_Parameters = @('Certificates', 'PrincipalsAllowedToDelegateToAccount', 'ServicePrincipalNames')
        $Null_Equal_Clear_Parameters | ForEach-Object {
            if ($PSBoundParameters.ContainsKey($_)) {
                if ($null -eq $PSBoundParameters[$_]) {
                    $PSBoundParameters['Clear'] += $_
                    [void]$PSBoundParameters.Remove($_)
                }
            }
        }
        Write-Verbose ('{0}|Calling Set-DSSObjectWrapper' -f $Function_Name)
        Set-DSSObjectWrapper -ObjectType 'User' -BoundParameters $PSBoundParameters

    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}
