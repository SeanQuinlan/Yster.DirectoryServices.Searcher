function Convert-GuidToHex {
    <#
    .SYNOPSIS
        Converts a GUID value to a HEX value suitable for using in LDAPFilter
    .DESCRIPTION

    .EXAMPLE

    #>

    [CmdletBinding()]
    param(
        # The GUID string.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $Guid
    )

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    try {
        if ($Guid -isnot [Guid]) {
            $Guid = [Guid]$Guid
        }
        # Return the HEX value, with every byte escaped.
        ($Guid.ToByteArray() | ForEach-Object { '\{0:X2}' -f $_ }) -join ''
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
