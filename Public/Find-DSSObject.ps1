function Find-DSSObject {
    <#
    .SYNOPSIS
        Finds an object in Active Directory.
    .DESCRIPTION
        Long description
    .EXAMPLE
        Example of how to use this script
    .EXAMPLE
        Another example of how to use this script
    #>

    [CmdletBinding()]
    param(
        # An LDAP filter to use for the search.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $LDAPFilter,

        # The base OU to start the search from.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $SearchBase,

        # The scope to search. Must be one of: Base, OneLevel, Subtree.
        [Parameter(Mandatory = $false)]
        [ValidateSet('Base','OneLevel','Subtree')]
        [String]
        $SearchScope,

        # The properties of any results to return.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        # The context to search - Domain or Forest.
        [Parameter(Mandatory = $false)]
        [ValidateSet('Domain','Forest')]
        [String]
        $Context = 'Domain',

        # The server to connect to.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
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
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name,$_.Key,($_.Value -join ' ')) }

    try {
        $Directory_Entry_Parameters = @{
            'Context' = $Context
        }
        if ($PSBoundParameters.ContainsKey('Server')) {
            $Directory_Entry_Parameters.Server = $Server
        }
        if ($PSBoundParameters.ContainsKey('SearchBase')) {
            $Directory_Entry_Parameters.SearchBase = $SearchBase
        }
        if ($PSBoundParameters.ContainsKey('Credential')) {
            $Directory_Entry_Parameters.Credential = $Credential
        }
        $Directory_Entry = Get-DSSDirectoryEntry @Directory_Entry_Parameters

        $Directory_Searcher_Arguments = @(
            $Directory_Entry
            $LDAPFilter
        )
        $Directory_Searcher = New-Object -TypeName 'System.DirectoryServices.DirectorySearcher' -ArgumentList $Directory_Searcher_Arguments

        if ($PSBoundParameters.ContainsKey('Properties')) {
            $Directory_Searcher.PropertiesToLoad.AddRange($Properties)
        }
        if ($PSBoundParameters.ContainsKey('SearchScope')) {
            $Directory_Searcher.SearchScope = $SearchScope
        }

        $Directory_Searcher_Results = $Directory_Searcher.FindAll()
        if ($Directory_Searcher_Results) {
            foreach ($Directory_Searcher_Result in $Directory_Searcher_Results) {
                $Result_Object = @{}
                $Directory_Searcher_Result.Properties.GetEnumerator() | ForEach-Object {
                    $Current_Searcher_Result_Property   = $_.Name
                    $Current_Searcher_Result_Value      = $($_.Value)
                    $Current_Searcher_Result_Syntax     = Get-DSSAttributeSyntax -Name $Current_Searcher_Result_Property

                    Write-Verbose ('{0}|Property={1} Syntax={2} Value={3}' -f $Function_Name,$Current_Searcher_Result_Property,$Current_Searcher_Result_Syntax,$Current_Searcher_Result_Value)

                    # Reformat certain attribute types
                    switch ($Current_Searcher_Result_Syntax) {
                        # GUID
                        '2.5.5.10' {
                            Write-Verbose ('{0}|Reformatting to GUID object: {1}' -f $Function_Name,$Current_Searcher_Result_Property)
                            $Current_Searcher_Result_Value = New-Object 'System.Guid' -ArgumentList @(,$Current_Searcher_Result_Value)
                        }

                        # SID
                        '2.5.5.17' {
                            Write-Verbose ('{0}|Reformatting to SID object: {1}' -f $Function_Name,$Current_Searcher_Result_Property)
                            $Current_Searcher_Result_Value = New-Object 'System.Security.Principal.SecurityIdentifier' -ArgumentList @($Current_Searcher_Result_Value,0)
                        }
                    }

                    $Result_Object[$Current_Searcher_Result_Property] = $Current_Searcher_Result_Value
                }

                # Return the retrieved AD object as a PS object
                New-Object -TypeName 'System.Management.Automation.PSObject' -Property $Result_Object
            }
        }
    }
    catch {

    }
}