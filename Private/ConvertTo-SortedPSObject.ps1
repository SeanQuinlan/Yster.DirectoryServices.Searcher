function ConvertTo-SortedPSObject {
    <#
    .SYNOPSIS
        Sorts a HashTable or PSObject alphabetically by properties and returns the result as a PSCustomObject.
    .DESCRIPTION
        Takes an input object of type HashTable or PSObject, and sorts it aphabetically by Property Name. A PSCustomObject with the sorted properties is returned.
    .EXAMPLE
        $SortedResults = ConvertTo-SortedPSObject -InputObject $ResultsObject
    #>

    [CmdletBinding()]
    param(
        # The input object.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $InputObject
    )

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    try {
        if ($InputObject -is [HashTable]) {
            # Sort results and then add to a new hashtable, as PSObject requires a hashtable as Property. GetEnumerator() piped into Sort-Object changes the output to an array.
            Write-Verbose ('{0}|HashTable type' -f $Function_Name)
            $Input_Object_Sorted = [Ordered]@{}
            $InputObject.GetEnumerator() | Sort-Object -Property 'Name' | ForEach-Object {
                $Input_Object_Sorted[$_.Name] = $_.Value
            }
            New-Object -TypeName 'System.Management.Automation.PSObject' -Property $Input_Object_Sorted
        } elseif ($InputObject -is [PSObject]) {
            Write-Verbose ('{0}|PSObject type' -f $Function_Name)
            $Input_Object_Sorted = New-Object -TypeName 'System.Management.Automation.PSObject'
            $InputObject.PSObject.Properties | Sort-Object -Property 'Name' | ForEach-Object {
                $Input_Object_Property = New-Object -TypeName 'System.Management.Automation.PSNoteProperty' -ArgumentList @($_.Name, $_.Value)
                $Input_Object_Sorted.PSObject.Properties.Add($Input_Object_Property)
            }
            $Input_Object_Sorted
        } else {
            Write-Error ('Unknown input object: {0}' -f $InputObject.GetType()) -ErrorAction 'Stop'
        }
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
