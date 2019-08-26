function Confirm-DSSObjectParameters {
    <#
    .SYNOPSIS
        Validates that the passed list of parameters is correct and does not contain conflicts.
    .DESCRIPTION
        Takes a block of parameters (usually $PSBoundParameters from one of the "Set" functions) and checks all the parameters for conflicts as well as validating the values to make sure they are correct.
        Returns a hashtable of Add/Clear/Remove/Replace parameters, which can be passed directly to Set-DSSRawObject.

        This is not meant to be used as an interactive function; it is used as a worker function by many of the other higher-level functions.
    .EXAMPLE
        $Set_Parameters = Confirm-DSSObjectParameters -BoundParameters $PSBoundParameters

        Validates the parameters supplied and throws an error if any are found. If all parameters are correct, returns a hashtable in a format suitable to be passed to Set-DSSRawObject.
    #>

    [CmdletBinding()]
    param(
        # A hashtable of parameters to validate.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [HashTable]
        $BoundParameters
    )

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    try {
        $Set_Choices = @('Remove', 'Add', 'Replace', 'Clear')
        $global:Set_Parameters = @{}

        # Add any other bound parameters, excluding the ones in $All_CommonParameters and in the $Set_Choices above.
        foreach ($Parameter_Key in $BoundParameters.Keys) {
            if (($All_CommonParameters + $Set_Choices) -notcontains $Parameter_Key) {
                if ($Combined_Calculated_Properties.Values -contains $Parameter_Key) {
                    $Parameter_Name = ($Combined_Calculated_Properties.GetEnumerator() | Where-Object { $_.Value -eq $Parameter_Key }).'Name'
                } else {
                    $Parameter_Name = $Parameter_Key
                }
                $Set_Parameters['Replace'] += @{
                    $Parameter_Name = $BoundParameters[$Parameter_Key]
                }
            }
        }

        foreach ($Set_Choice in $Set_Choices) {
            if ($BoundParameters.ContainsKey($Set_Choice)) {
                $Set_Choice_Values = Get-Variable -Name $Set_Choice -ValueOnly

                if ($Set_Choice -eq 'Clear') {
                    $New_Set_Choice_Values = New-Object -TypeName 'System.Collections.Generic.List[Object]'
                    foreach ($Current_Value in $Set_Choice_Values) {
                        if ($Combined_Calculated_Properties.Values -contains $Current_Value) {
                            $LDAP_Property = ($Combined_Calculated_Properties.GetEnumerator() | Where-Object { $_.Value -eq $Current_Value }).'Name'
                            $Property_To_Add = $LDAP_Property
                        } else {
                            $Property_To_Add = $Current_Value
                        }
                        if ($Set_Parameters['Replace'].Keys -contains $Property_To_Add) {
                            $Conflicting_Parameter = $Property_To_Add
                        }
                        $New_Set_Choice_Values.Add($Property_To_Add)
                    }
                } else {
                    $New_Set_Choice_Values = @{}
                    foreach ($Current_Value in $Set_Choice_Values.GetEnumerator()) {
                        if ($Combined_Calculated_Properties.Values -contains $Current_Value.Name) {
                            $LDAP_Property = ($Combined_Calculated_Properties.GetEnumerator() | Where-Object { $_.Value -eq $Current_Value.Name }).'Name'
                            $Property_To_Add = @{
                                $LDAP_Property = $Current_Value.Value
                            }
                        } else {
                            $Property_To_Add = @{
                                $Current_Value.Name = $Current_Value.Value
                            }
                        }
                        if ($Set_Parameters['Replace'].Keys -contains $Property_To_Add.Keys) {
                            $Conflicting_Parameter = $($Property_To_Add.Keys)
                        }
                        $New_Set_Choice_Values += $Property_To_Add
                    }
                }
                if ($Conflicting_Parameter) {
                    # Get the Microsoft Alias property as well (if there is one), to make the error message better.
                    if ($Combined_Calculated_Properties.Keys -contains $Conflicting_Parameter) {
                        $Conflicting_Parameter = ($Conflicting_Parameter, ($Combined_Calculated_Properties[$Conflicting_Parameter])) -join '/'
                    }
                    $Terminating_ErrorRecord_Parameters = @{
                        'Exception'    = 'System.ArgumentException'
                        'ID'           = 'DSS-{0}' -f $Function_Name
                        'Category'     = 'InvalidArgument'
                        'TargetObject' = $Object_Directory_Entry
                        'Message'      = 'Cannot specify attribute "{0}" as a direct parameter and via the Add/Remove/Replace/Clear parameters as well' -f $Conflicting_Parameter
                    }
                    $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                    $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                } else {
                    $Set_Parameters[$Set_Choice] = $Set_Choice_Values
                    [void]$BoundParameters.Remove($Set_Choice)
                }
            }
        }

        # Perform some additional validation on the supplied values. This needs to be done here in order to validate the values passed in via Add/Replace/Remove hashtables.
        foreach ($Choice in @('Replace', 'Add')) {
            if ($Set_Parameters[$Choice]) {
                foreach ($Key in @($Set_Parameters[$Choice].Keys)) {
                    switch -Regex ($Key) {
                        'homedrive' {
                            if ($Key -notmatch '^[A-Z]{1}:') {
                                $Terminating_ErrorRecord_Parameters = @{
                                    'Exception'    = 'System.ArgumentException'
                                    'ID'           = 'DSS-{0}' -f $Function_Name
                                    'Category'     = 'InvalidArgument'
                                    'TargetObject' = $Key
                                    'Message'      = 'HomeDrive value must be a single letter followed by a colon. Eg. "H:"'
                                }
                                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                            }
                        }
                        'accountexpires' {
                            try {
                                if ($Set_Parameters[$Choice][$Key].ToString() -ne '0') {
                                    $Check_Date = Get-Date -Date $Set_Parameters[$Choice][$Key]
                                    Write-Verbose ('{0}|Reformatting DateTime to FileTime: {1}' -f $Function_Name, $Key)
                                    $Set_Parameters[$Choice][$Key] = $Check_Date.ToFileTime()
                                }
                                # These numbers have to be passed as strings in order to set them.
                                $Set_Parameters[$Choice][$Key] = $Set_Parameters[$Choice][$Key].ToString()
                            } catch {
                                $Terminating_ErrorRecord_Parameters = @{
                                    'Exception'      = 'System.FormatException'
                                    'ID'             = 'DSS-{0}' -f $Function_Name
                                    'Category'       = 'InvalidArgument'
                                    'TargetObject'   = $Check_Date
                                    'Message'        = $_.Exception.InnerException.Message
                                    'InnerException' = $_.Exception
                                }
                                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                            }
                        }
                    }
                }
                $Set_Parameters_To_Validate += $Set_Parameters[$Choice].GetEnumerator()
            }
        }

        # Return the $Set_Parameters hashtable.
        $Set_Parameters
    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}
