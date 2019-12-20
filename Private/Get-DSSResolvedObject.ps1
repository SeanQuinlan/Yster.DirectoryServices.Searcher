function Get-DSSResolvedObject {
    <#
    .SYNOPSIS
        Takes a list of supplied strings and resolves them to Active Directory objects.
    .DESCRIPTION
        Resolves the supplied list of strings and outputs an object or array of objects with adspath and distinguishedname properties.

        This is used in other functions that need to resolve a subset of objects that are passed through another property, like a list of group members that are passed to Add-DSSGroupMember.
    .EXAMPLE

    .NOTES

    #>

    [CmdletBinding()]
    param(
        # The input string or strings to resolve to Active Directory objects.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $InputSet,

        # The context to search - Domain, Forest or Server.
        [Parameter(Mandatory = $false)]
        [ValidateSet('Domain', 'Forest')]
        [String]
        $Context = 'Domain',

        # The server/domain/forest to run the query on.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('Forest', 'Domain')]
        [String]
        $Server,

        # The credential to use for access.
        [Parameter(Mandatory = $false)]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    $global:Output_Objects = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'
    $Object_Search_Properties = @(
        'SAMAccountName'
        'DistinguishedName'
        'ObjectSID'
        'ObjectGUID'
    )

    try {
        foreach ($Input_Object in $InputSet) {
            $Output_Object = $null
            foreach ($Object_Search_Property in $Object_Search_Properties) {
                if ($Object_Search_Property -eq 'ObjectGUID') {
                    # Only proceed if the $Input_Object string is a valid GUID.
                    if ([System.Guid]::TryParse($Input_Object, [ref][System.Guid]::Empty)) {
                        $Input_Object = (Convert-GuidToHex -Guid $Input_Object)
                    } else {
                        break
                    }
                }
                $Object_Search_Parameters = @{
                    'OutputFormat' = 'DirectoryEntry'
                    'LDAPFilter'   = ('({0}={1})' -f $Object_Search_Property, $Input_Object)
                }
                $Input_Object_Result = Find-DSSRawObject @Common_Search_Parameters @Object_Search_Parameters
                if ($Input_Object_Result.Count) {
                    $Output_Object = @{
                        'Object' = $Input_Object_Result
                        'Path'   = $Input_Object_Result.'adspath'
                        'Name'   = $($Input_Object_Result.'distinguishedname')
                    }
                    Write-Verbose ('{0}|Found object: {1}' -f $Function_Name, $Output_Object['Name'])
                    break
                }
            }
            if (-not $Output_Object) {
                $Terminating_ErrorRecord_Parameters = @{
                    'Exception'    = 'System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException'
                    'ID'           = 'DSS-{0}' -f $Function_Name
                    'Category'     = 'ObjectNotFound'
                    'TargetObject' = $Input_Object
                    'Message'      = 'Cannot find object with Identity of "{0}"' -f $Input_Object
                }
                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
            } else {
                $Output_Objects.Add($Output_Object)
            }
        }

        # Return the array of output objects.
        $Output_Objects

    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}
