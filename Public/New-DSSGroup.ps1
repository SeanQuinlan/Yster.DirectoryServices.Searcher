function New-DSSGroup {
    <#
    .SYNOPSIS
        Creates a new group object in Active Directory.
    .DESCRIPTION
        Creates a group object in Active Directory, using the properties supplied.
    .EXAMPLE
        New-DSSGroup -Name 'Sales Users' -Path 'OU=Groups,OU=Company,DC=contoso,DC=com' -GroupScope Universal

        Creates the group object in the specified OU path.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/new-adgroup
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
        # -Description 'UK Sales Group'
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

        # The category of the group to set. Must be one of: Security, Distribution.
        # An example of using this property is:
        #
        # -GroupCategory Security
        [Parameter(Mandatory = $false)]
        [ValidateSet('Security', 'Distribution')]
        [String]
        $GroupCategory = 'Security',

        # The scope of the group to set. Must be one of: DomainLocal, Global, Universal.
        # An example of using this property is:
        #
        # -GroupScope Universal
        [Parameter(Mandatory = $true)]
        [ValidateSet('DomainLocal', 'Global', 'Universal')]
        [String]
        $GroupScope,

        # The value that will be set as the HomePage of the object.
        # An example of using this property is:
        #
        # -HomePage 'intranet.contoso.com/sales'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('WWWHomePage')]
        [String]
        $HomePage,

        # Sets the ManagedBy property of the group. This value can be one of the following object types:
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
        # -Name 'SalesUsers'
        [Parameter(Mandatory = $true, Position = 0)]
        [String]
        $Name,

        # A hashtable of attributes/properties and values to set on the object.
        # Multiple values for the same property can be separated by commas.
        # Multiple properties can also be specified by separating them with semi-colons.
        # See below for some examples:
        #
        # -OtherAttributes @{wwwhomepage='www.contoso.com'}
        # -OtherAttributes @{secretary='rsmith','bjones','krichards'}
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
        $Server
    )

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    try {
        Write-Verbose ('{0}|Calling New-DSSObjectWrapper' -f $Function_Name)
        New-DSSObjectWrapper -ObjectType 'Group' -BoundParameters $PSBoundParameters

    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}
