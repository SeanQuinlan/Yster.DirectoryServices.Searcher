function Get-DSSRootDSE {
    <#
    .SYNOPSIS
        Gets the special RootDSE object from the directory server.
    .DESCRIPTION
        Retrieves the RootDSE object which provides information about the directory schema, version, supported capabilities and other LDAP server details
    .EXAMPLE
        (Get-RootDSE).schemaNamingContext

        This returns the naming context (DistinguishedName) of the Schema container.
    .EXAMPLE
        $DomainDN = (Get-RootDSE).defaultNamingContext

        Returns the DistinguishedName of the Active Directory domain.
    #>

    [CmdletBinding()]
    param(
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
            'Context'       = 'Domain'
            'SearchBase'    = 'RootDSE'
        }
        if ($PSBoundParameters.ContainsKey('Server')) {
            $Directory_Entry_Parameters.Server = $Server
        }
        if ($PSBoundParameters.ContainsKey('Credential')) {
            $Directory_Entry_Parameters.Credential = $Credential
        }
        $Directory_Entry = Get-DSSDirectoryEntry @Directory_Entry_Parameters

        # Format the DirectoryEntry object to match that returned from Find-DSSObject.
        Write-Verbose ('{0}|Formatting result' -f $Function_Name)
        $RootDSE_Result_To_Return = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'

        $Result_Object = @{}
        $Directory_Entry.Properties.PropertyNames | ForEach-Object {
            $RootDSE_Property   = $_
            $RootDSE_Value      = $($Directory_Entry.$_)
            Write-Verbose ('{0}|Property={1} Value={2}' -f $Function_Name,$RootDSE_Property,$RootDSE_Value)

            $Result_Object[$RootDSE_Property] = $RootDSE_Value
        }

        # Sort results and then add to a new hashtable, as PSObject requires a hashtable as Property. GetEnumerator() piped into Sort-Object changes the output to an array.
        $Result_Object_Sorted = [ordered]@{}
        $Result_Object.GetEnumerator() | Sort-Object -Property 'Name' | ForEach-Object {
            $Result_Object_Sorted[$_.Name] = $_.Value
        }
        $RootDSE_Result_Object = New-Object -TypeName 'System.Management.Automation.PSObject' -Property $Result_Object_Sorted
        $RootDSE_Result_To_Return.Add($RootDSE_Result_Object)

        # Return the RootDSE object.
        $RootDSE_Result_To_Return
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
