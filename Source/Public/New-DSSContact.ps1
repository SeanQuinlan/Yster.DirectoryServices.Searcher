function New-DSSContact {
    <#
    .SYNOPSIS
        Creates a new contact in Active Directory.
    .DESCRIPTION
        Creates a contact object in Active Directory, using the properties supplied.
    .EXAMPLE
        New-DSSContact -Name 'Supplier01' -Path 'OU=Contacts,OU=Company,DC=contoso,DC=com'

        Creates the contact object in the specified OU path.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/activedirectory/new-adobject
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
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

        # The value that will be set as the EmployeeID of the object.
        # An example of using this property is:
        #
        # -EmployeeID 'JSMITH41'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $EmployeeID,

        # The value that will be set as the Fax number of the object.
        # An example of using this property is:
        #
        # -Fax '000-1111 2222'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('FacsimileTelephoneNumber')]
        [String]
        $Fax,

        # The value that will be set as the GivenName of the object.
        # An example of using this property is:
        #
        # -GivenName 'John'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('FirstName')]
        [String]
        $GivenName,

        # The value that will be set as the HomePage of the object.
        # An example of using this property is:
        #
        # -HomePage 'intranet.contoso.com/sales'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('WWWHomePage')]
        [String]
        $HomePage,

        # The value that will be set as the Middle Initial(s) of the object.
        # An example of using this property is:
        #
        # -Initials 'AJ'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Initials,

        # Sets the Manager property of the contact. This value can be one of the following object types:
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

        # The value that will be set as the MobilePhone of the object.
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

        # The value that will be set as the OtherName of the contact. This sets the LDAP property middleName, which is what this property is used for.
        # An example of using this property is:
        #
        # -OtherName 'Richard'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('MiddleName')]
        [String]
        $OtherName,

        # An OU path to create the object in.
        # An example of using this property is:
        #
        # -Path = 'OU=Contacts,OU=Company,DC=contoso,DC=com'
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
        $StreetAddress,

        # The value that will be set as the Surname of the object.
        # An example of using this property is:
        #
        # -Surname 'Smith'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('LastName', 'Sn')]
        [String]
        $Surname,

        # The value that will be set as the Title of the object. This is the value that appears as "Job Title" in the GUI.
        # An example of using this property is:
        #
        # -Title 'Manager'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('JobTitle')]
        [String]
        $Title
    )

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    try {
        Write-Verbose ('{0}|Calling New-DSSObjectWrapper' -f $Function_Name)
        New-DSSObjectWrapper -ObjectType 'Contact' -BoundParameters $PSBoundParameters

    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}