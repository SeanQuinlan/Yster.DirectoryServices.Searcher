function New-DSSObjectWrapper {
    <#
    .SYNOPSIS
        A wrapper function to check any New-DSS cmdlet for valid parameters and then create the object in Active Directory.
    .DESCRIPTION
        This will check through the PSBoundParameters of the calling function and confirm their validity.
        If all tests pass, it will call New-DSSRawObject to actually create the object in Active Directory.

        This is not meant to be used as an interactive function; it is a wrapper function around the New-DSS cmdlets, in order to reduce reuse of code.
    .EXAMPLE
        New-DSSObjectWrapper -ObjectType 'User' -BoundParameters $PSBoundParameters

        Creates the user object with the supplied parameters.
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        # A hashtable of the PSBoundParameters that were passed from the calling function.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $BoundParameters,

        # The type of AD object that has been wrapped.
        [Parameter(Mandatory = $true)]
        [String]
        $ObjectType
    )

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object {
        if ($_.Value -is [Hashtable]) {
            Write-Verbose ("{0}|Arguments: {1}:`n{2}" -f $Function_Name, $_.Key, ($_.Value | Format-Table -AutoSize | Out-String).Trim())
        } else {
            Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' '))
        }
    }

    try {
        $Common_Parameters = @('Context', 'Server', 'Credential')
        $Common_Search_Parameters = @{}
        foreach ($Parameter in $Common_Parameters) {
            if ($BoundParameters.ContainsKey($Parameter)) {
                $Common_Search_Parameters[$Parameter] = Get-Variable -Name $Parameter -ValueOnly
                [void]$BoundParameters.Remove($Parameter)
            }
        }

        $Non_Property_Parameters = @('Name', 'Path')
        $Other_Parameters = @{}
        foreach ($Parameter in $Non_Property_Parameters) {
            if ($BoundParameters.ContainsKey($Parameter)) {
                $Other_Parameters[$Parameter] = Get-Variable -Name $Parameter -ValueOnly
                [void]$BoundParameters.Remove($Parameter)
            }
        }

        $New_Parameters = @{}
        if ($BoundParameters.Count) {
            $New_Parameters = Confirm-DSSObjectParameters -BoundParameters $BoundParameters -Type 'New'
        }

        Write-Verbose ('{0}|Calling New-DSSRawObject' -f $Function_Name)
        New-DSSRawObject @Common_Search_Parameters @New_Parameters @Other_Parameters -Type $ObjectType

    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}
