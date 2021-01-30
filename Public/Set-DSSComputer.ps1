function Set-DSSComputer {
    <#
    .SYNOPSIS
        Modifies an LDAP attribute of a Computer object from Active Directory.
    .DESCRIPTION
        Queries Active Directory for a specific computer object and then modifies one or more attributes on this object.
        The object can be specified using one of the following
            - DistinguishedName
            - ObjectGUID (GUID)
            - ObjectSID (SID)
            - SAMAccountName
    .EXAMPLE
        Set-DSSComputer -DistinguishedName 'CN=APPSRV01,OU=Servers,DC=contoso,DC=com' -Replace @{Description='Application Server 01'}

        Sets the Description attribute of the APPSRV01 computer object, replacing any value that is already there.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/set-adcomputer
    #>

    [CmdletBinding(DefaultParameterSetName = 'DistinguishedName', SupportsShouldProcess = $true)]
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

        # A property or an array of properties to clear.
        # See below for some examples:
        #
        # -Clear Description
        # -Clear company,postalcode,street
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

        # The value that will be set as the Description of the object.
        # An example of using this property is:
        #
        # -Description 'Primary DC'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Description,

        # The value that will be set as the DisplayName of the object.
        # An example of using this property is:
        #
        # -DisplayName 'Marketing Server, London'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DisplayName,

        # The DistinguishedName of the computer.
        [Parameter(Mandatory = $true, ParameterSetName = 'DistinguishedName')]
        [ValidateNotNullOrEmpty()]
        [Alias('DN')]
        [String]
        $DistinguishedName,

        # The value that will be set as the DNSHostName of the object.
        # An example of using this property is:
        #
        # -DNSHostName 'server1.corp.contoso.com'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DNSHostName,

        # Specifies whether an object is enabled.
        # This sets the Enabled flag of the UserAccountControl attribute of the object.
        # An example of using this property is:
        #
        # -Enabled $false
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $Enabled,

        # The value that will be set as the HomePage of the object.
        # An example of using this property is:
        #
        # -HomePage 'intranet.contoso.com'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('WWWHomePage')]
        [String]
        $HomePage,

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

        # The value that will be set as the Location of the object.
        # An example of using this property is:
        #
        # -Location 'San Franciso DC1'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Location,

        # Sets the ManagedBy property of the computer. This value can be one of the following object types:
        # ..DistinguishedName
        # ..ObjectSID (SID)
        # ..ObjectGUID (GUID)
        # ..SAMAccountName
        #
        # Some examples of using this property are:
        #
        # -ManagedBy 'rsmith'
        # -ManagedBy 'CN=rsmith,OU=Users,OU=Company,DC=contoso,DC=com'
        # -ManagedBy 'S-1-5-21-3387319312-2301824641-2614994224-7110'
        # -ManagedBy 'f4fcc8dc-bd82-41d0-bc0a-5c44350bbb62'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ManagedBy,

        # The ObjectGUID of the computer.
        [Parameter(Mandatory = $true, ParameterSetName = 'GUID')]
        [ValidateNotNullOrEmpty()]
        [Alias('GUID')]
        [String]
        $ObjectGUID,

        # The ObjectSID of the computer.
        [Parameter(Mandatory = $true, ParameterSetName = 'SID')]
        [ValidateNotNullOrEmpty()]
        [Alias('SID')]
        [String]
        $ObjectSID,

        # The value that will be set as the OperatingSystem of the object.
        # An example of using this property is:
        #
        # -OperatingSystem 'Windows Server 2016 Standard'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $OperatingSystem,

        # The value that will be set as the OperatingSystemHotfix of the object.
        # An example of using this property is:
        #
        # -OperatingSystemHotfix 'HF001'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $OperatingSystemHotFix,

        # The value that will be set as the OperatingSystemServicePack of the object.
        # An example of using this property is:
        #
        # -OperatingSystemServicePack 'SP1'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $OperatingSystemServicePack,

        # The value that will be set as the OperatingSystemVersion of the object.
        # An example of using this property is:
        #
        # -OperatingSystemVersion '10.0 (14393)'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $OperatingSystemVersion,

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

        # A hashtable that defines the PrincipalsAllowedToDelegateToAccount to add, remove or replace on the object.
        # Add and remove will add or remove individual entries (if found). Replace will replace all entries with just those specified.
        # The hashtable KEY has to be add, remove or replace.
        # The corresponding hashtable VALUE can be a single string or multiple strings (separated by commas).
        # The VALUE references a computer object, and can be supplied in one of the following forms:
        # ..DistinguishedName
        # ..ObjectSID (SID)
        # ..ObjectGUID (GUID)
        # ..SAMAccountName
        #
        # See below for some examples:
        # -PrincipalsAllowedToDelegateToAccount @{Add='WINSRV01$'}
        # -PrincipalsAllowedToDelegateToAccount @{Add='0911f77e-862a-4bd7-a073-282289ad51ab','S-1-5-21-739503189-1020924195-124678973-1172'}
        # -PrincipalsAllowedToDelegateToAccount @{Remove='0911f77e-862a-4bd7-a073-282289ad51ab'}
        # -PrincipalsAllowedToDelegateToAccount @{Replace='S-1-5-21-739503189-1020924195-124678973-1172','WINSRV01$'}
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
        [HashTable]
        $PrincipalsAllowedToDelegateToAccount,

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
        [HashTable]
        $Remove,

        # A property name and a value or set of values that will be used to replace the existing property values.
        # Multiple values for the same property can be separated by commas.
        # Multiple properties can also be specified by separating them with semi-colons.
        # See below for some examples:
        #
        # -Replace @{description='Marketing Server'}
        # -Replace @{otherTelephone='000-0000-0000','111-1111-1111'}
        # -Replace @{displayname='Server03'; kerberosencryptiontype='None'; cannotchangepassword=$true}
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

        # The SAMAccountName of the computer.
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
        # -ServicePrincipalNames @{Add='HOST/SERVER01'}
        # -ServicePrincipalNames @{Add='HOST/SERVER01','HOST/SERVER01.contoso.com'}
        # -ServicePrincipalNames @{Remove='HOST/SERVER01'}
        # -ServicePrincipalNames @{Replace='HOST/SERVER02','HOST/SERVER02.contoso.com'}
        #
        # Multiple actions can also be specified by providing multiple lines within the hashtable. For example:
        # -ServicePrincipalNames @{Remove='HOST/SERVER01'; Add='HOST/SERVER02'}
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
        [HashTable]
        $ServicePrincipalNames,

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
        # -UserPrincipalName 'srv03@contoso.com'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('UPN')]
        [String]
        $UserPrincipalName
    )

    # Parameters to add:
    # -----------------
    # AuthenticationPolicy
    # AuthenticationPolicySilo
    # Certificates

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    try {
        $Null_Equal_Clear_Parameters = @('ServicePrincipalNames', 'PrincipalsAllowedToDelegateToAccount')
        $Null_Equal_Clear_Parameters | ForEach-Object {
            if ($PSBoundParameters.ContainsKey($_)) {
                if ($null -eq $PSBoundParameters[$_]) {
                    $PSBoundParameters['Clear'] += $_
                    [void]$PSBoundParameters.Remove($_)
                }
            }
        }
        Write-Verbose ('{0}|Calling Set-DSSObjectWrapper' -f $Function_Name)
        Set-DSSObjectWrapper -ObjectType 'Computer' -BoundParameters $PSBoundParameters

    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}
