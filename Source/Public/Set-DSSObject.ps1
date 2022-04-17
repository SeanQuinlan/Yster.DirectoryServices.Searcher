function Set-DSSObject {
    <#
    .SYNOPSIS
        Modifies an LDAP attribute of an object from Active Directory.
    .DESCRIPTION
        Queries Active Directory for a specific object and then modifies one or more attributes on this object.
        The object can be specified using one of the following
            - DistinguishedName
            - ObjectGUID (GUID)
            - ObjectSID (SID)
            - SAMAccountName
    .EXAMPLE
        Set-DSSObject -DistinguishedName 'CN=SQL Servers,OU=Servers,DC=contoso,DC=com' -Replace @{Description='SQL Servers'}

        Sets the Description attribute of the "SQL Servers" object, replacing any value that is already there.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/set-adobject
    #>

    [CmdletBinding(DefaultParameterSetName = 'DistinguishedName', SupportsShouldProcess = $true)]
    param(
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

        # Specifies whether an account is required to change it's password when next logging on.
        # An example of using this property is:
        #
        # -ChangePasswordAtLogon $true
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $ChangePasswordAtLogon,

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

        # The DistinguishedName of the object.
        [Parameter(Mandatory = $true, ParameterSetName = 'DistinguishedName')]
        [ValidateNotNullOrEmpty()]
        [Alias('DN')]
        [String]
        $DistinguishedName,

        # Specifies whether an object is enabled.
        # This sets the Enabled flag of the UserAccountControl attribute of the object.
        # An example of using this property is:
        #
        # -Enabled $false
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $Enabled,

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

        # The ObjectGUID of the object.
        [Parameter(Mandatory = $true, ParameterSetName = 'GUID')]
        [ValidateNotNullOrEmpty()]
        [Alias('GUID')]
        [String]
        $ObjectGUID,

        # The ObjectSID of the object.
        [Parameter(Mandatory = $true, ParameterSetName = 'SID')]
        [ValidateNotNullOrEmpty()]
        [Alias('SID')]
        [String]
        $ObjectSID,

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
        # -Remove @{postaladdress='1 First St'}
        # -Remove @{businesscategory='Sales','Head Office'}
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
        # -Replace @{description='Head Office'}
        # -Replace @{businesscategory='Marketing', 'HeadOffice'}
        # -Replace @{displayname='Marketing Users'; street='Main St'; wwwhomepage='marketing.contoso.com'}
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

        # The SAMAccountName of the account.
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

        # Specifies whether an account is trusted for Kerberos delegation.
        # This sets the TrustedForDelegation flag of the UserAccountControl attribute.
        # An example of using this property is:
        #
        # -TrustedForDelegation $true
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $TrustedForDelegation
    )

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    try {
        Write-Verbose ('{0}|Calling Set-DSSObjectWrapper' -f $Function_Name)
        Set-DSSObjectWrapper -ObjectType 'Object' -BoundParameters $PSBoundParameters

    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}