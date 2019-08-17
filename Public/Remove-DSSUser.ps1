function Remove-DSSUser {
    <#
    .SYNOPSIS
        Removes a specific user object from Active Directory.
    .DESCRIPTION
        Queries Active Directory for a specific user object and then deletes it, based on one of the following specified parameters:
            - DistinguishedName
            - ObjectSID (SID)
            - ObjectGUID (GUID)
            - SAMAccountName
    .EXAMPLE
        Remove-DSSUser -ObjectGUID 'b675195d-e637-447e-ad26-baded4df1ba0'

        Deletes the user with the above GUID.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/remove-aduser
    #>

    [CmdletBinding(DefaultParameterSetName = 'SAM', SupportsShouldProcess = $true)]
    param(
        # The SAMAccountName of the user.
        [Parameter(Mandatory = $true, ParameterSetName = 'SAM')]
        [ValidateNotNullOrEmpty()]
        [Alias('SAM')]
        [String]
        $SAMAccountName,

        # The DistinguishedName of the user.
        [Parameter(Mandatory = $true, ParameterSetName = 'DistinguishedName')]
        [ValidateNotNullOrEmpty()]
        [Alias('DN')]
        [String]
        $DistinguishedName,

        # The ObjectSID of the user.
        [Parameter(Mandatory = $true, ParameterSetName = 'SID')]
        [ValidateNotNullOrEmpty()]
        [Alias('SID')]
        [String]
        $ObjectSID,

        # The ObjectGUID of the user.
        [Parameter(Mandatory = $true, ParameterSetName = 'GUID')]
        [ValidateNotNullOrEmpty()]
        [Alias('GUID')]
        [String]
        $ObjectGUID,

        # The context to search - Domain or Forest.
        [Parameter(Mandatory = $false)]
        [ValidateSet('Domain', 'Forest')]
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
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    $Set_Parameters = @{
        'SetType' = 'RemoveObject'
    }

    # This will add the -Confirm parameter if ConfirmPreference is set high enough.
    # The Set-DSSRawObject doesn't have a default ConfirmImpact set, so this passes the ConfirmImpact from this function if required.
    if (-not $PSBoundParameters.ContainsKey('Confirm')) {
        $ConfirmImpact = 'High'
        if ([System.Management.Automation.ConfirmImpact]::$ConfirmImpact.Value__ -ge [System.Management.Automation.ConfirmImpact]::$ConfirmPreference.Value__) {
            Write-Verbose ('{0}|Adding Confirm parameter' -f $Function_Name)
            $Set_Parameters['Confirm'] = $True
        }
    }

    try {
        Write-Verbose ('{0}|Calling Set-DSSRawObject' -f $Function_Name)
        Set-DSSRawObject @Set_Parameters @PSBoundParameters
    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}
