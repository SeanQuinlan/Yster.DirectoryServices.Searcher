function Remove-DSSOrganizationalUnit {
    <#
    .SYNOPSIS
        Removes a specific organizational unit (OU) object from Active Directory.
    .DESCRIPTION
        Queries Active Directory for a specific OU object and then deletes it, based on one of the following specified parameters:
            - DistinguishedName
            - ObjectSID (SID)
            - ObjectGUID (GUID)
            - SAMAccountName
    .EXAMPLE
        Remove-DSSOrganizationalUnit -DistinguishedName 'OU=Sales,OU=Depts,DC=contoso,DC=com'

        Deletes the Sales OU.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/remove-adorganizationalunit
    #>

    [CmdletBinding(DefaultParameterSetName = 'SAM', SupportsShouldProcess = $true)]
    param(
        # The DistinguishedName of the organizational unit.
        [Parameter(Mandatory = $true, ParameterSetName = 'DistinguishedName')]
        [ValidateNotNullOrEmpty()]
        [Alias('DN')]
        [String]
        $DistinguishedName,

        # The ObjectGUID of the organizational unit.
        [Parameter(Mandatory = $true, ParameterSetName = 'GUID')]
        [ValidateNotNullOrEmpty()]
        [Alias('GUID')]
        [String]
        $ObjectGUID,

        # Delete all child objects recursively.
        [Parameter(Mandatory = $false)]
        [Switch]
        $Recursive,

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
        'SetType' = 'Remove'
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
