function Confirm-DSSObjectParameters {
    <#
    .SYNOPSIS
        Validates that the passed list of parameters is correct and does not contain conflicts.
    .DESCRIPTION
        Takes a block of parameters (usually $PSBoundParameters from one of the "Set" or "New" functions) and checks all the parameters for conflicts as well as validating the values to make sure they are correct.
        Returns a hashtable of parameters which can then be passed directly to Set-DSSRawObject or New-DSSRawObject.

        This is not meant to be used as an interactive function; it is used as a worker function by many of the other higher-level functions.
    .EXAMPLE
        $Set_Parameters = Confirm-DSSObjectParameters -BoundParameters $PSBoundParameters -Type 'Set'

        Validates the parameters supplied and throws an error if any are found. If all parameters are correct, returns a hashtable in a format suitable to be passed to Set-DSSRawObject.
    #>

    [CmdletBinding()]
    param(
        # A hashtable of parameters to validate.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [HashTable]
        $BoundParameters,

        # The type of parameter validation to perform.
        [Parameter(Mandatory = $true)]
        [ValidateSet('New', 'Set')]
        [String]
        $Type
    )

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    try {
        $Return_Parameters = @{}

        switch ($Type) {
            'New' {
                $Parameter_Choices = @('Properties')
                $Parameter_Default = 'Properties'
                $Hashtable_Validkeys = @('Add', 'Remove', 'Replace')
                $Validation_Choices = @('Properties')
            }
            'Set' {
                $Parameter_Choices = @('Add', 'Remove', 'Replace', 'Clear')
                $Parameter_Default = 'Replace'
                $Hashtable_Validkeys = @('Add', 'Remove', 'Replace')
                $Validation_Choices = @('Add', 'Replace')
            }
        }

        # Add any other bound parameters, excluding the ones in $All_CommonParameters and in the $Parameter_Choices above.
        foreach ($Parameter_Key in $BoundParameters.Keys) {
            if (($All_CommonParameters + $Parameter_Choices) -notcontains $Parameter_Key) {
                # Any parameters that are supplied as hashtables will be "broken down" into their relevant key-value pairs.
                if ($BoundParameters[$Parameter_Key] -is [HashTable]) {
                    if ($Hashtable_Validkeys) {
                        Write-Verbose ('{0}|Checking parameter hashtable for valid keys: {1}' -f $Function_Name, $Parameter_Key)
                        foreach ($Key_Name in $BoundParameters[$Parameter_Key].Keys) {
                            if ($Hashtable_Validkeys -notcontains $Key_Name) {
                                $Terminating_ErrorRecord_Parameters = @{
                                    'Exception'    = 'System.ArgumentException'
                                    'ID'           = 'DSS-{0}' -f $Function_Name
                                    'Category'     = 'InvalidArgument'
                                    'TargetObject' = $Object_Directory_Entry
                                    'Message'      = 'Cannot validate argument on parameter "{0}": Key "{1}" is invalid. Hashtable can only contain the following as keys: {2}' -f $Parameter_Key, $Key_Name, ($Hashtable_Validkeys -join ', ')
                                }
                                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                            }
                        }
                        Write-Verbose ('{0}|Breaking down parameter: {1}' -f $Function_Name, $Parameter_Key)
                        foreach ($Key_Name in $BoundParameters[$Parameter_Key].Keys) {
                            if ($Microsoft_Alias_Names -contains $Parameter_Key) {
                                $LDAP_Parameter_Key = ($Microsoft_Alias_Properties.GetEnumerator() | Where-Object { $_.Value -eq $Parameter_Key }).'Name'
                            } else {
                                $LDAP_Parameter_Key = $Parameter_Key
                            }
                            Write-Verbose ('{0}|Adding "{1}" with values: {2} - {3}' -f $Function_Name, $Key_Name, $LDAP_Parameter_Key, ($BoundParameters[$Parameter_Key][$Key_Name] -join ' '))
                            $Return_Parameters[$Key_Name] += @{
                                $LDAP_Parameter_Key = $BoundParameters[$Parameter_Key][$Key_Name]
                            }
                        }
                    } else {
                        Write-Verbose ('{0}|Breaking down parameter: {1}' -f $Function_Name, $Parameter_Key)
                        foreach ($Key_Name in $BoundParameters[$Parameter_Key].Keys) {
                            Write-Verbose ('{0}|Parameter: {1}|Key: {2}' -f $Function_Name, $Parameter_Key, $Key_Name)
                            if ($Microsoft_Alias_Names -contains $Key_Name) {
                                $LDAP_Parameter_Key = ($Microsoft_Alias_Properties.GetEnumerator() | Where-Object { $_.Value -eq $Key_Name }).'Name'
                            } else {
                                $LDAP_Parameter_Key = $Key_Name
                            }
                            if (-not $Return_Parameters[$Parameter_Default]) {
                                $Return_Parameters[$Parameter_Default] = @{}
                            }
                            if ($Return_Parameters[$Parameter_Default][$LDAP_Parameter_Key]) {
                                $Conflicting_Parameter = $Key_Name
                                # Get the Microsoft Alias property as well (if there is one), to make the error message better.
                                if ($Combined_Calculated_Properties.Keys -contains $Conflicting_Parameter) {
                                    $Conflicting_Parameter = ($Conflicting_Parameter, ($Combined_Calculated_Properties[$Conflicting_Parameter])) -join '/'
                                }
                                $Terminating_ErrorRecord_Parameters = @{
                                    'Exception'    = 'System.ArgumentException'
                                    'ID'           = 'DSS-{0}' -f $Function_Name
                                    'Category'     = 'InvalidArgument'
                                    'TargetObject' = $Object_Directory_Entry
                                    'Message'      = 'Cannot specify attribute "{0}" as a direct parameter and via the {1} as well' -f $Conflicting_Parameter, ("{0} parameters" -f ($Parameter_Choices -join '/'))
                                }
                                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                            } else {
                                Write-Verbose ('{0}|Adding "{1}" with values: {2} - {3}' -f $Function_Name, $Parameter_Default, $LDAP_Parameter_Key, ($BoundParameters[$Parameter_Key][$Key_Name] -join ' '))
                                $Return_Parameters[$Parameter_Default] += @{
                                    $LDAP_Parameter_Key = $BoundParameters[$Parameter_Key][$Key_Name]
                                }
                            }
                        }
                    }
                } else {
                    if ($Combined_Calculated_Properties.Values -contains $Parameter_Key) {
                        $Parameter_Name = ($Combined_Calculated_Properties.GetEnumerator() | Where-Object { $_.Value -eq $Parameter_Key }).'Name'
                    } else {
                        $Parameter_Name = $Parameter_Key
                    }
                    Write-Verbose ('{0}|Adding bound parameter: {1} - {2}' -f $Function_Name, $Parameter_Name, $BoundParameters[$Parameter_Key])
                    $Return_Parameters[$Parameter_Default] += @{
                        $Parameter_Name = $BoundParameters[$Parameter_Key]
                    }
                }
            }
        }

        # Add the parameters in $Parameter_Choices.
        foreach ($Parameter_Choice in $Parameter_Choices) {
            if ($BoundParameters.ContainsKey($Parameter_Choice)) {
                $Parameter_Choice_Values = Get-Variable -Name $Parameter_Choice -ValueOnly

                if ($Parameter_Choice -eq 'Clear') {
                    $New_Parameter_Choice_Values = New-Object -TypeName 'System.Collections.Generic.List[Object]'
                    foreach ($Current_Value in $Parameter_Choice_Values) {
                        if ($Combined_Calculated_Properties.Values -contains $Current_Value) {
                            $LDAP_Property = ($Combined_Calculated_Properties.GetEnumerator() | Where-Object { $_.Value -eq $Current_Value }).'Name'
                            $Property_To_Add = $LDAP_Property
                        } else {
                            $Property_To_Add = $Current_Value
                        }
                        if ($Return_Parameters[$Parameter_Default].Keys -contains $Property_To_Add) {
                            $Conflicting_Parameter = $Property_To_Add
                        }
                        $New_Parameter_Choice_Values.Add($Property_To_Add)
                    }
                } else {
                    $New_Parameter_Choice_Values = @{}
                    foreach ($Current_Value in $Parameter_Choice_Values.GetEnumerator()) {
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
                        if ($Return_Parameters[$Parameter_Default].Keys -contains $Property_To_Add.Keys) {
                            $Conflicting_Parameter = $($Property_To_Add.Keys)
                        }
                        $New_Parameter_Choice_Values += $Property_To_Add
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
                        'Message'      = 'Cannot specify attribute "{0}" as a direct parameter and via the {1} as well' -f $Conflicting_Parameter, ("{0} parameters" -f ($Parameter_Choices -join '/'))
                    }
                    $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                    $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
                } else {
                    Write-Verbose ('{0}|Adding "{1}" with values: {2}' -f $Function_Name, $Parameter_Choice, ($Parameter_Choice_Values -join ' '))
                    $Return_Parameters[$Parameter_Choice] += $Parameter_Choice_Values
                }
            }
        }

        # Perform some additional validation on the supplied values. This needs to be done here in order to validate the values passed in via nested hashtables.
        foreach ($Validation_Choice in $Validation_Choices) {
            if ($Return_Parameters[$Validation_Choice]) {
                foreach ($Key in @($Return_Parameters[$Validation_Choice].Keys)) {
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
                                if ($Return_Parameters[$Validation_Choice][$Key].ToString() -ne '0') {
                                    $Check_Date = Get-Date -Date $Return_Parameters[$Validation_Choice][$Key]
                                    Write-Verbose ('{0}|Reformatting DateTime to FileTime: {1}' -f $Function_Name, $Key)
                                    $Return_Parameters[$Validation_Choice][$Key] = $Check_Date.ToFileTime()
                                }
                                # These numbers have to be passed as strings in order to set them.
                                $Return_Parameters[$Validation_Choice][$Key] = $Return_Parameters[$Validation_Choice][$Key].ToString()
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
                $Return_Parameters_To_Validate += $Return_Parameters[$Validation_Choice].GetEnumerator()
            }
        }

        # Return the hashtable of updated and validated values.
        $Return_Parameters
    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}
