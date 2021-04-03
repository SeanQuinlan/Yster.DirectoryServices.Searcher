function Move-DSSObject {
    <#
    .SYNOPSIS
        Moves an Active Directory object or container of objects.
    .DESCRIPTION
        Moves the specified object to the supplied target path.
        The object can be specified using one of the following:
            - DistinguishedName
            - ObjectGUID (GUID)
            - ObjectSID (SID)
            - SAMAccountName
    .EXAMPLE
        Move-DSSObject -DistinguishedName 'CN=SQL Servers,OU=Servers,DC=contoso,DC=com' -TargetPath 'OU=Servers,OU=Headquarters,DC=contoso,DC=com'

        Moves the "SQL Servers" object to the new location.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/move-adobject
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

        # The DistinguishedName of the account.
        [Parameter(Mandatory = $true, ParameterSetName = 'DistinguishedName')]
        [ValidateNotNullOrEmpty()]
        [Alias('DN')]
        [String]
        $DistinguishedName,

        # The ObjectGUID of the account.
        [Parameter(Mandatory = $true, ParameterSetName = 'GUID')]
        [ValidateNotNullOrEmpty()]
        [Alias('GUID')]
        [String]
        $ObjectGUID,

        # The ObjectSID of the account.
        [Parameter(Mandatory = $true, ParameterSetName = 'SID')]
        [ValidateNotNullOrEmpty()]
        [Alias('SID')]
        [String]
        $ObjectSID,

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

        # The DistinguishedName of the destination OU or container.
        # An example of using this property is:
        #
        # -TargetPath 'OU=Servers,OU=Headquarters,DC=contoso,DC=com'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $TargetPath,

        # When moving between domains, supply the FQDN of the destination domain controller to use.
        # An example of using this property is:
        #
        # -TargetServer 'dc01.admin.contoso.com'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $TargetServer
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

        $Identity_Parameters = @('DistinguishedName', 'ObjectGUID', 'ObjectSID', 'SAMAccountName')
        foreach ($Parameter in $Identity_Parameters) {
            if ($PSBoundParameters.ContainsKey($Parameter)) {
                $Directory_Search_Type = $Parameter
                $Directory_Search_Value = $PSBoundParameters[$Parameter]
                $LDAPFilter = '({0}={1})' -f $Directory_Search_Type, $Directory_Search_Value
            }
        }
        $Directory_Search_Parameters = @{
            'LDAPFilter'   = $LDAPFilter
            'OutputFormat' = 'DirectoryEntry'
        }

        $Object_Directory_Entry = Find-DSSRawObject @Common_Search_Parameters @Directory_Search_Parameters
        if ($Object_Directory_Entry) {
            $Target_Search_Parameters = $Common_Search_Parameters.PSBase.Clone()
            if ($PSBoundParameters.ContainsKey('TargetServer')) {
                $Target_Search_Parameters['Server'] = $TargetServer
            }
            Write-Verbose ('{0}|Checking if TargetPath exists')
            $Check_TargetPath = Get-DSSOrganizationalUnit @Target_Search_Parameters -DistinguishedName $TargetPath
            if ($Check_TargetPath) {
                $Target_Directory_Entry = Get-DSSDirectoryEntry @Target_Search_Parameters -SearchBase $TargetPath
                try {
                    Write-Verbose ('{0}|Moving object to TargetPath: {1}' -f $Function_Name, $TargetPath)
                    $Object_Directory_Entry.MoveTo($Target_Directory_Entry)
                } catch {
                    # This exception is thrown when you specify the domain name in TargetServer, not the FQDN.
                    if ($_.Exception.InnerException.ErrorCode -eq '-2147016663') {
                        $Terminating_ErrorRecord_Parameters = @{
                            'Exception'      = 'System.DirectoryServices.DirectoryServicesCOMException'
                            'ID'             = 'DSS-{0}' -f $Function_Name
                            'Category'       = 'AuthenticationError'
                            'TargetObject'   = $Object_Directory_Entry
                            'Message'        = 'Unable to authenticate to the server. Ensure that the FQDN is specified.'
                            'InnerException' = $_.Exception
                        }
                        $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                        $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                    } else {
                        throw $_.Exception.InnerException
                    }
                }
            } else {
                $Terminating_ErrorRecord_Parameters = @{
                    'Exception'    = 'System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException'
                    'ID'           = 'DSS-{0}' -f $Function_Name
                    'Category'     = 'ObjectNotFound'
                    'TargetObject' = $Check_TargetPath
                    'Message'      = 'Unable to find TargetPath "{0}"' -f $TargetPath
                }
                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
            }
        } else {
            $Terminating_ErrorRecord_Parameters = @{
                'Exception'    = 'System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException'
                'ID'           = 'DSS-{0}' -f $Function_Name
                'Category'     = 'ObjectNotFound'
                'TargetObject' = $Object_Directory_Entry
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
