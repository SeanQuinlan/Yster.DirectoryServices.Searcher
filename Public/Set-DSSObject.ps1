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
        Set-DSSObject -DistinguishedName 'CN=SQL Servers,OU=Servers,DC=contoso,DC=com' -Replace @{Description='SQL Servers'}

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
        [HashTable]
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
        [HashTable]
        $Replace,

        # The server or domain to connect to.
        # See below for some examples:
        #
        # -Server DC01
        # -Server 'dc01.contoso.com'
        # -Server CONTOSO
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Server
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
