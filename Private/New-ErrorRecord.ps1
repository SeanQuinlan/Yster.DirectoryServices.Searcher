function New-ErrorRecord {
    <#
    .SYNOPSIS
        Create an ErrorRecord object that can be used to output a custom error message.
    .DESCRIPTION
        Long description
    .EXAMPLE
        Example of how to use this script
    #>

    [CmdletBinding()]
    param(
        # The exception used to describe the error.
        [Parameter(Mandatory = $true, Position = 1)]
        [String]
        $Exception,

        # The ID of the exception.
        [Parameter(Mandatory = $true, Position = 2)]
        [String]
        $ID,

        # The category of the exception.
        [Parameter(Mandatory = $true, Position = 3)]
        [ValidateSet(
            # From: https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.errorcategory?view=powershellsdk-1.1.0
            'AuthenticationError',
            'CloseError',
            'ConnectionError',
            'DeadlockDetected',
            'DeviceError',
            'FromStdErr',
            'InvalidArgument',
            'InvalidData',
            'InvalidOperation',
            'InvalidResult',
            'InvalidType',
            'LimitsExceeded',
            'MetadataError',
            'NotEnabled',
            'NotImplemented',
            'NotInstalled',
            'ObjectNotFound',
            'OpenError',
            'OperationStopped',
            'OperationTimeout',
            'ParserError',
            'PermissionDenied',
            'ProtocolError',
            'QuotaExceeded',
            'ReadError',
            'ResourceBusy',
            'ResourceExists',
            'ResourceUnavailable',
            'SecurityError',
            'SyntaxError',
            'WriteError'
        )]
        [System.Management.Automation.ErrorCategory]
        $Category,

        # The object against which the cmdlet was operating when the error occurred.
        [Parameter(Mandatory = $false, Position = 4)]
        [Object]
        $TargetObject = $null,

        # A custom error message to display with the error.
        [Parameter(Mandatory = $false, Position = 5)]
        [String]
        $Message,

        # The inner exception that is the cause of this exception.
        [Parameter(Mandatory = $false, Position = 6)]
        [Object]
        $InnerException
    )

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    if ($PSBoundParameters.ContainsKey('Message') -and $PSBoundParameters.ContainsKey('InnerException')) {
        $Exception_Arguments = $Message, $InnerException
    } elseif ($PSBoundParameters.ContainsKey('Message')) {
        $Exception_Arguments = $Message
    }
    $ErrorException = New-Object -TypeName $Exception -ArgumentList $Exception_Arguments
    $ErrorRecord_Arguments = @($ErrorException, $ID, $Category, $TargetObject)

    # Return the ErrorRecord object
    New-Object -TypeName 'System.Management.Automation.ErrorRecord' -ArgumentList $ErrorRecord_Arguments
}
