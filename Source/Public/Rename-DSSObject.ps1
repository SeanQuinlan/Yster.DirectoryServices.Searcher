function Rename-DSSObject {
    <#
    .SYNOPSIS
        Renames an Active Directory object.
    .DESCRIPTION
        Renames the "CN" attribute of the specified object.
        The object can be identified using one of the following:
            - DistinguishedName
            - ObjectGUID (GUID)
            - ObjectSID (SID)
    .EXAMPLE
        Rename-DSSObject -DistinguishedName 'CN=SQL Servers,OU=Servers,DC=contoso,DC=com' -NewName 'London SQL Servers'

        Renames the "SQL Servers" object to "London SQL Servers".
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/activedirectory/rename-adobject
    #>

    [CmdletBinding(DefaultParameterSetName = 'DistinguishedName', SupportsShouldProcess = $true)]
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

        # The DistinguishedName of the object.
        [Parameter(Mandatory = $true, ParameterSetName = 'DistinguishedName')]
        [ValidateNotNullOrEmpty()]
        [Alias('DN')]
        [String]
        $DistinguishedName,

        # The new name of the object.
        # An example of using this property is:
        #
        # -NewName 'All Servers'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $NewName,

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
        $ObjectType = 'Object'
        $Common_Parameters = @('Context', 'Server', 'Credential')
        $Common_Search_Parameters = @{}
        foreach ($Parameter in $Common_Parameters) {
            if ($PSBoundParameters.ContainsKey($Parameter)) {
                $Common_Search_Parameters[$Parameter] = Get-Variable -Name $Parameter -ValueOnly
            }
        }

        $Identity_Parameters = @('DistinguishedName', 'ObjectGUID', 'ObjectSID')
        foreach ($Parameter in $Identity_Parameters) {
            if ($PSBoundParameters.ContainsKey($Parameter)) {
                $Directory_Search_Type = $Parameter
                $Directory_Search_Value = $PSBoundParameters[$Parameter]
                $LDAPFilter = '({0}={1})' -f $Directory_Search_Type, $Directory_Search_Value
            }
        }
        $Directory_Search_Parameters = @{
            'LDAPFilter' = $LDAPFilter
            'Properties' = 'ParentOU'
        }

        $Object_Directory_Search = Find-DSSObject @Common_Search_Parameters @Directory_Search_Parameters
        if ($Object_Directory_Search) {
            Write-Verbose ('{0}|Checking if NewName exists in ParentOU: {1}' -f $Function_Name, $Object_Directory_Search.'parentou')
            $NewName_Search_Parameters = @{
                'LDAPFilter'  = '(cn={0})' -f $NewName
                'SearchBase'  = $Object_Directory_Search.'parentou'
                'SearchScope' = 'OneLevel'
            }
            $Check_NewName = Find-DSSObject @Common_Search_Parameters @NewName_Search_Parameters
            if ($Check_NewName) {
                $Terminating_ErrorRecord_Parameters = @{
                    'Exception'    = 'System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectExistsException'
                    'ID'           = 'DSS-{0}' -f $Function_Name
                    'Category'     = 'InvalidData'
                    'TargetObject' = $Check_NewName
                    'Message'      = 'An object with CN "{0}" already exists in OU: {1}' -f $NewName, $Object_Directory_Search.'parentou'
                }
                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
            } else {
                $Directory_Entry_Properties = @{
                    'LDAPFilter'   = '(distinguishedname={0})' -f $Object_Directory_Search.'distinguishedname'
                    'OutputFormat' = 'DirectoryEntry'
                }
                $Object_Directory_Entry = Find-DSSRawObject @Common_Search_Parameters @Directory_Entry_Properties
                Write-Verbose ('{0}|Renaming object "{1}" to NewName: {2}' -f $Function_Name, $Object_Directory_Search.'distinguishedname', $NewName)
                $Object_Directory_Entry.Rename(('CN={0}' -f $NewName))
            }
        } else {
            $Terminating_ErrorRecord_Parameters = @{
                'Exception'    = 'System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException'
                'ID'           = 'DSS-{0}' -f $Function_Name
                'Category'     = 'ObjectNotFound'
                'TargetObject' = $Object_Directory_Search
                'Message'      = 'Cannot find {0} with {1} of "{2}"' -f $ObjectType, $Directory_Search_Type, $Directory_Search_Value
            }
            $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        }

    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}
