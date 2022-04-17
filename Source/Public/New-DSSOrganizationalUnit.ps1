function New-DSSOrganizationalUnit {
    <#
    .SYNOPSIS
        Creates a new organizational unit in Active Directory.
    .DESCRIPTION
        Creates an organizational unit in Active Directory, using the properties supplied.
    .EXAMPLE
        New-DSSOrganizationalUnit -Name 'Sales' -Path 'OU=Groups,OU=Company,DC=contoso,DC=com'

        Creates the organizational unit 'Sales' in the above path.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/activedirectory/new-adorganizationalunit
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        # The value that will be set as the City of the object.
        # An example of using this property is:
        #
        # -City 'San Francisco'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $City,

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

        # The value that will be set as the Description of the object.
        # An example of using this property is:
        #
        # -Description 'London Users'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Description,

        # The value that will be set as the DisplayName of the object.
        # An example of using this property is:
        #
        # -DisplayName 'All Marketing Users'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DisplayName,

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
        # An example of using this property is:
        #
        # -Name 'Users'
        [Parameter(Mandatory = $true, Position = 0)]
        [String]
        $Name,

        # A hashtable of attributes/properties and values to set on the object.
        # Multiple values for the same property can be separated by commas.
        # Multiple properties can also be specified by separating them with semi-colons.
        # See below for some examples:
        #
        # -OtherAttributes @{wwwhomepage='www.contoso.com'}
        # -OtherAttributes @{postofficebox='123','234','345'}
        # -OtherAttributes @{wwwhomepage='www.contoso.com'; telephonenumber='000-000-0000'; displayname='Marketing Users'}
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $OtherAttributes,

        # An OU path to create the object in.
        # An example of using this property is:
        #
        # -Path = 'OU=Groups,OU=Company,DC=contoso,DC=com'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        # The value that will be set as the PostalCode of the object.
        # An example of using this property is:
        #
        # -PostalCode '12345'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $PostalCode,

        # Specifies whether the object is protected from accidental deletion.
        # An example of using this property is:
        #
        # -ProtectedFromAccidentalDeletion $false
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $ProtectedFromAccidentalDeletion,

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
        $StreetAddress
    )

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    try {
        Write-Verbose ('{0}|Calling New-DSSObjectWrapper' -f $Function_Name)
        New-DSSObjectWrapper -ObjectType 'OrganizationalUnit' -BoundParameters $PSBoundParameters

    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}
