function Convert-GuidToHex {
    <#
    .SYNOPSIS
        Converts a GUID value to a HEX value suitable for using in LDAPFilter.
    .DESCRIPTION
        Takes a GUID or string in GUID format, and converts that into a HEX value, with each byte escaped with a backslash.
    .EXAMPLE
        Convert-GuidToHex -Guid 'eaa2e65d-fe54-4fe2-9f4e-acf9f65a2323'
    .NOTES
        References:
        https://unlockpowershell.wordpress.com/2010/07/01/powershell-search-ad-for-a-guid/
    #>

    [CmdletBinding()]
    param(
        # The GUID or GUID string.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $Guid
    )

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    # Check if the supplied GUID is actually a parseable GUID.
    if ([System.Guid]::TryParse($Guid, [ref][System.Guid]::Empty)) {
        if ($Guid -isnot [System.Guid]) {
            $Guid = [System.Guid]$Guid
        }
        # Return the HEX value, with every byte escaped.
        ($Guid.ToByteArray() | ForEach-Object { '\{0:X2}' -f $_ }) -join ''
    } else {
        $Terminating_ErrorRecord_Parameters = @{
            'Exception'    = 'System.Management.Automation.PSInvalidCastException'
            'ID'           = 'DSS-{0}' -f $Function_Name
            'Category'     = 'InvalidOperation'
            'TargetObject' = $Guid
            'Message'      = ('Unable to parse GUID: {0}.' -f $Guid)
        }
        $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
        $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
    }
}
