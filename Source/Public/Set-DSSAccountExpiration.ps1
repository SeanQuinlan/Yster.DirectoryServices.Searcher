function Set-DSSAccountExpiration {
    <#
    .SYNOPSIS
        Sets the Account Expiration field for an Active Directory account.
    .DESCRIPTION
        Sets the Account Expiration attribute on a computer, user or service account in Active Directory, using either a specific DateTime value, or a TimeSpan from the current time.
    .EXAMPLE
        Set-DSSAccountExpiration -SAMAccountName 'Guest' -DateTime (Get-Date).AddDays(90)

        Sets the account expiration date on the "Guest" account to 90 days in the future.
    .EXAMPLE
        $ExpiryDate = Get-Date '25/12/1999'
        Set-DSSAccountExpiration -ObjectSID 'S-1-5-21-3515480276-2049723633-1306762111-1103' -DateTime $ExpiryDate

        Sets the account expiration date on the user with the above SID, to the specific date in the ExpiryDate variable.
    .EXAMPLE
        $TimeSpan = New-TimeSpan -Days 60
        Set-DSSAccountExpiration -DistinguishedName 'CN=JSmith,OU=Marketing,OU=Accounts,DC=contoso,DC=com' -TimeSpan $TimeSpan

        Sets the account expiration date on the "JSmith" account to a date 60 days in the future.
    .NOTES
        References:
        https://docs.microsoft.com/en-us/powershell/module/addsadministration/set-adaccountexpiration
    #>

    [CmdletBinding(DefaultParameterSetName = 'SAM', SupportsShouldProcess = $true)]
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

        # A date and time value that specifies when the account expires.
        # If no time is specified, then the time will be set to 00:00:00 on the supplied date.
        # Some examples of using this property are:
        #
        # -DateTime '25/12/1999'
        # -DateTime '25/12/1999 17:30:00'
        # -DateTime (Get-Date).AddDays(90)
        [Parameter(Mandatory = $false, ParameterSetName = 'DateTime')]
        [Parameter(Mandatory = $false, ParameterSetName = 'SAM')]
        [ValidateScript(
            {
                if ($_ -gt '01/01/1601 00:00:00') {
                    $true
                } else {
                    throw "Value has to be greater than 01/01/1601 00:00:00"
                }
            }
        )]
        [DateTime]
        $DateTime,

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

        # A date and time value that specifies when the account expires.
        # If no time is specified, then the time will be set to 00:00:00 on the supplied date.
        # Some examples of using this property are:
        #
        # -DateTime '25/12/1999'
        # -DateTime '25/12/1999 17:30:00'
        # -DateTime (Get-Date).AddDays(90)
        [Parameter(Mandatory = $false, ParameterSetName = 'TimeSpan')]
        [Parameter(Mandatory = $false, ParameterSetName = 'SAM')]
        [ValidateNotNullOrEmpty()]
        [TimeSpan]
        $TimeSpan
    )

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    try {
        if (-not ($PSBoundParameters.ContainsKey('DateTime') -or $PSBoundParameters.ContainsKey('TimeSpan'))) {
            $Terminating_ErrorRecord_Parameters = @{
                'Exception' = 'System.ArgumentException'
                'ID'        = 'DSS-{0}' -f $Function_Name
                'Category'  = 'InvalidArgument'
                'Message'   = 'One of the following parameters is required: TimeSpan, DateTime'
            }
            $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } elseif ($PSBoundParameters.ContainsKey('DateTime') -and $PSBoundParameters.ContainsKey('TimeSpan')) {
            $Terminating_ErrorRecord_Parameters = @{
                'Exception' = 'System.ArgumentException'
                'ID'        = 'DSS-{0}' -f $Function_Name
                'Category'  = 'InvalidArgument'
                'Message'   = 'Only one of the following parameters can be specified: TimeSpan, DateTime'
            }
            $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        }

        if ($PSBoundParameters.ContainsKey('DateTime')) {
            [void]$PSBoundParameters.Remove('DateTime')
        } elseif ($PSBoundParameters.ContainsKey('TimeSpan')) {
            $DateTime = (Get-Date) + $TimeSpan
            [void]$PSBoundParameters.Remove('TimeSpan')
        }

        Write-Verbose ('{0}|Calling Set-DSSObjectWrapper' -f $Function_Name)
        $PSBoundParameters['AccountExpirationDate'] = $DateTime
        Set-DSSObjectWrapper -ObjectType 'Account' -BoundParameters $PSBoundParameters

    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}
