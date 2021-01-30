function New-DSSObject {
    <#
    .SYNOPSIS
        Creates a new object in Active Directory.
    .DESCRIPTION
        Creates an object in Active Directory, using the Type and properties supplied.
    .EXAMPLE
        New-DSSObject -Name 'jsmith' -Type 'user' -Path 'OU=Users,OU=Company,DC=contoso,DC=com'

        Creates the user object in the specified OU path.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/new-adobject
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
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

        # The name of the object to create. This will be the CN attribute for the object.
        # See below for some examples:
        #
        # -Name 'jsmith'
        # -Name 'SRVSALES05N'
        [Parameter(Mandatory = $true, Position = 0)]
        [String]
        $Name,

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

        # An OU path to create the object in.
        # An example of using this property is:
        #
        # -Path = 'OU=Users,OU=Company,DC=contoso,DC=com'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        # Specifies whether the object is protected from accidental deletion.
        # An example of using this property is:
        #
        # -ProtectedFromAccidentalDeletion $true
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

        # The type of AD object to create.
        # See below for some examples:
        #
        # -Type 'user'
        # -Type 'computer'
        # -Type 'organizationalunit'
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Type
    )

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    try {
        Write-Verbose ('{0}|Calling New-DSSObjectWrapper' -f $Function_Name)
        [void]$PSBoundParameters.Remove('Type')
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
