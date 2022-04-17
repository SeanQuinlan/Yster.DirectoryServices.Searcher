function New-DSSComputer {
    <#
    .SYNOPSIS
        Creates a new computer object in Active Directory.
    .DESCRIPTION
        Creates a computer object in Active Directory, using the properties supplied.
    .EXAMPLE
        New-DSSComputer -Name 'WIN-SRV01' -Path 'OU=Computers,OU=Company,DC=contoso,DC=com'

        Creates the computer object in the specified OU path.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/activedirectory/new-adcomputer
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        # A date and time value that specifies when the account expires.
        # If no time is specified, then the time will be set to 00:00:00 on the supplied date.
        # Some examples of using this property are:
        #
        # -AccountExpirationDate '25/12/1999'
        # -AccountExpirationDate '25/12/1999 17:30:00'
        # -AccountExpirationDate (Get-Date).AddDays(90)
        [Parameter(Mandatory = $false)]
        [ValidateScript(
            {
                if ($_ -gt '01/01/1601 00:00:00') {
                    $true
                } else {
                    throw "Value has to be greater than 01/01/1601 00:00:00"
                }
            }
        )]
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
        # -Description 'Marketing Server 02'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Description,

        # The value that will be set as the DisplayName of the object.
        # An example of using this property is:
        #
        # -DisplayName 'Marketing Server'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DisplayName,

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
        # -HomePage 'intranet.contoso.com/sales'
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

        # Sets the ManagedBy property of the object. This value can be one of the following object types:
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

        # The name of the object to create. This will be the CN attribute for the object.
        # See below for some examples:
        #
        # -Name 'WIN-SRV01'
        # -Name 'SRVSALES05N'
        [Parameter(Mandatory = $true, Position = 0)]
        [String]
        $Name,

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
        # -Path = 'OU=Computers,OU=Company,DC=contoso,DC=com'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        # A list of PrincipalsAllowedToDelegateToAccount for the object.
        # The VALUE references an AD object, and can be supplied in one of the following forms:
        # ..DistinguishedName
        # ..ObjectSID (SID)
        # ..ObjectGUID (GUID)
        # ..SAMAccountName
        #
        # See below for some examples:
        #
        # -PrincipalsAllowedToDelegateToAccount 'WINSRV01$'
        # -PrincipalsAllowedToDelegateToAccount '0911f77e-862a-4bd7-a073-282289ad51ab', 'S-1-5-21-739503189-1020924195-124678973-1172'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Array]
        $PrincipalsAllowedToDelegateToAccount,

        # Specifies whether the object is protected from accidental deletion.
        # An example of using this property is:
        #
        # -ProtectedFromAccidentalDeletion $true
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $ProtectedFromAccidentalDeletion,

        # The value to set for the SAMAccountName.
        # By default, this is set to the same as the Name field, with a "$" appended, eg. COMP001$ for the Name "COMP001"
        #
        # An example of using this property is:
        #
        # -SAMAccountName 'WIN-SRV01$'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
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

        # A list of ServicePrincipalNames for the object.
        # See below for some examples:
        #
        # -ServicePrincipalNames 'HOST/SERVER01'
        # -ServicePrincipalNames 'HOST/SERVER01','HOST/SERVER01.contoso.com'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('ServicePrincipalName')]
        [Array]
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

        # The value that will be set as the UserPrincipalName of the object.
        # An example of using this property is:
        #
        # -UserPrincipalName 'srv03@contoso.com'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('UPN')]
        [String]
        $UserPrincipalName
    )

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    try {
        if (-not $SAMAccountName) {
            $PSBoundParameters['SAMAccountName'] = ('{0}$' -f $Name)
        }
        $Convert_To_Hashtable_Parameters = @('Certificates', 'PrincipalsAllowedToDelegateToAccount', 'ServicePrincipalNames')
        $Convert_To_Hashtable_Parameters | ForEach-Object {
            if ($PSBoundParameters.ContainsKey($_)) {
                $Parameter_New_Value = @{'Replace' = $PSBoundParameters[$_] }
                [void]$PSBoundParameters.Remove($_)
                [void]$PSBoundParameters.Add($_, $Parameter_New_Value)
            }
        }
        Write-Verbose ('{0}|Calling New-DSSObjectWrapper' -f $Function_Name)
        New-DSSObjectWrapper -ObjectType 'Computer' -BoundParameters $PSBoundParameters

    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}
