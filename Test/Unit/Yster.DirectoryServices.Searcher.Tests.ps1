
# Some helpful links:
# https://stackoverflow.com/questions/62497134/pester-5-0-2-beforeall-block-code-not-showing-up-in-describe-block
# https://vexx32.github.io/2018/12/20/Searching-PowerShell-Abstract-Syntax-Tree/
# https://pester.dev/docs/usage/discovery-and-run
# https://pester.dev/docs/usage/data-driven-tests#migrating-from-pester-v4

BeforeDiscovery {
    $Module_Root = Join-Path -Path $PSScriptRoot -ChildPath '..\..\Source'
    $Module_Path = Get-ChildItem -Path $Module_Root -Filter 'Yster.DirectoryServices.Searcher.psd1'
    $Module_Information = Import-Module -Name $Module_Path.PSPath -Force -ErrorAction 'Stop' -PassThru
    $Module_ExportedFunctions = $Module_Information.ExportedFunctions.Values.Name

    $TestCases = New-Object -TypeName System.Collections.Generic.List[Hashtable]
    $Module_ExportedFunctions | ForEach-Object {
        $TestCases.Add(@{FunctionName = $_})
    }

    $Optional_Parameters = @(
        @{'ParameterName' = 'Context'}
        @{'ParameterName' = 'Credential'}
        @{'ParameterName' = 'Server'}
    )
    $Optional_Parameters_Exclude_Functions = @('Get-DSSAllPossibleAttributes', 'Get-DSSDomain', 'Get-DSSForest', 'Get-DSSRootDSE')
    $Optional_Parameters_Functions = $TestCases | Where-Object { $Optional_Parameters_Exclude_Functions -notcontains $_['FunctionName'] }

    $Required_Parameters_Find = @(
        @{'ParameterName' = 'PageSize'}
    )
    $Required_Parameters_Find_Functions = $TestCases | Where-Object { $_['FunctionName'] -match '^Find' }

    $OrgUnit_Prohibited_Parameters = @(
        @{'ParameterName' = 'ObjectSID'}
        @{'ParameterName' = 'SAMAccountName'}
    )
    $OrgUnit_Functions = $TestCases | Where-Object { $_['FunctionName'] -match 'OrganizationalUnit$' }

    $Required_Parameters_FindGet = @(
        @{'ParameterName' = 'Properties'; 'Alias' = 'Property'}
    )
    $Required_Parameters_FindGet_Exclude_Functions = @('Get-DSSAllPossibleAttributes', 'Get-DSSRootDSE')
    $Required_Parameters_FindGet_Functions = $TestCases | Where-Object { ($_['FunctionName'] -match '^Find|^Get') -and ($Required_Parameters_FindGet_Exclude_Functions -notcontains $_['FunctionName']) }
}

Describe 'Function Validation for: <FunctionName>' -Tags @('Module', 'Unit') -ForEach $TestCases {
    BeforeAll {
        $Function_Contents = Get-Content -Path function:$FunctionName
        $Function_AST = [System.Management.Automation.Language.Parser]::ParseInput($Function_Contents, [ref]$null, [ref]$null)
        $Function_Name_Declaration = '$Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name'
    }

    Context 'Function Help' {
        It '<FunctionName> has Synopsis' {
            $Function_AST.GetHelpContent().Synopsis | Should -Not -BeNullOrEmpty
        }
        It '<FunctionName> has Description' {
            $Function_AST.GetHelpContent().Description | Should -Not -BeNullOrEmpty
        }
        It '<FunctionName> has at least 1 Code example' {
            $Function_AST.GetHelpContent().Examples.Count | Should -BeGreaterThan 0
        }
        # Insipired from: https://lazywinadmin.com/2016/08/powershellpester-make-sure-your-comment.html
        It '<FunctionName> has indented comment block' {
            $null = $Function_Contents -match '(?ms)\s+\<\#.*\>\#?'
            $Function_CommentsNotIndented = $matches[0].Split("`n") -notmatch '^[\t|\s{4}]'
            $Function_CommentsNotIndented.Count | Should -Be 0
        }
        # Inspired from: https://lazywinadmin.com/2016/08/powershellpester-make-sure-your.html
        It '<FunctionName> has parameters separated by blank lines' {
            $Function_ParamBlock_Text = $Function_AST.ParamBlock.Extent.Text.Split("`n").Trim()
            $Function_ParameterNames = $Function_AST.ParamBlock.Parameters.Name.VariablePath.UserPath
            $Function_ParameterBlocks = $Function_ParameterNames | Where-Object {
                $Function_AST.ParamBlock.Extent.Text -match ('\${0}.*,' -f $_) # Only match those with a comma after the parameter (ie. exclude the last parameter).
            }

            foreach ($ParameterName in $Function_ParameterBlocks) {
                # Select-String's LineNumber properties start from 1 since they are designed to be output to the console.
                # This is useful because it effectively gets the line "after" the match, which is the line we want to check is a blank line.
                $Function_Param_LineNumber = $Function_ParamBlock_Text | Select-String ('{0}.*,$' -f $ParameterName) | Select-Object -ExpandProperty LineNumber
                [String]::IsNullOrWhiteSpace($Function_ParamBlock_Text[$Function_Param_LineNumber]) | Should -Be $true
            }
        }
    }

    Context 'Function Parameters' {
        It '<FunctionName> has no global variables defined' {
            # Find all variables, including those in sub-functions (the $true at the end).
            $Function_Nodes = $Function_AST.FindAll({return ($args[0] -is [System.Management.Automation.Language.VariableExpressionAst])}, $true)
            $Function_Nodes | Where-Object { ($_.VariablePath.UserPath -match 'global') } | Should -Be $null
        }
    }

    Context 'Function Variables' {
        It '<FunctionName> has $Function_Name variable declaration' {
            # Only look for the $Function_Name variable declaration in the main function, not sub-functions.
            $Function_Nodes = $Function_AST.FindAll({return ($args[0] -is [System.Management.Automation.Language.VariableExpressionAst])}, $false)
            $Function_Nodes | Where-Object { ($_.VariablePath.UserPath -eq 'Function_Name') -and ($_.Parent.Extent.Text -eq $Function_Name_Declaration) } | Should -Be $true
        }
    }
}

Describe 'Optional Parameters Validation for: <FunctionName>' -Tags @('Module', 'Unit') -ForEach $Optional_Parameters_Functions {
    BeforeAll {
        $Function_Contents = Get-Content -Path function:$FunctionName
        $Function_AST = [System.Management.Automation.Language.Parser]::ParseInput($Function_Contents, [ref]$null, [ref]$null)
    }

    Context 'Optional Parameters' {
        It ('<FunctionName> has optional parameter: <ParameterName>') -Foreach $Optional_Parameters {
            $Optional_Parameter_Check = $Function_AST.ParamBlock.Parameters | Where-Object { $_.Name.Extent.Text -eq ('${0}' -f $ParameterName) }
            $Optional_Parameter_Check | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Required Parameters Validation for Find Function: <FunctionName>' -Tags @('Module', 'Unit') -ForEach $Required_Parameters_Find_Functions {
    BeforeAll {
        $Function_Contents = Get-Content -Path function:$FunctionName
        $Function_AST = [System.Management.Automation.Language.Parser]::ParseInput($Function_Contents, [ref]$null, [ref]$null)
    }

    Context 'Required Parameters' {
        It ('<FunctionName> has required parameter: <ParameterName>') -Foreach $Required_Parameters_Find {
            $Required_Parameter_Check = $Function_AST.ParamBlock.Parameters | Where-Object { $_.Name.Extent.Text -eq ('${0}' -f $ParameterName) }
            $Required_Parameter_Check | Should -Not -BeNullOrEmpty
        }
    }
}

# OrganizationalUnits do not have SIDs or SAMAccountNames, so ensure that no function has those parameters.
Describe 'Prohibited Parameters for OrganizationalUnit Function: <FunctionName>' -Tags @('Module', 'Unit') -ForEach $OrgUnit_Functions {
    BeforeAll {
        $Function_Contents = Get-Content -Path function:$FunctionName
        $Function_AST = [System.Management.Automation.Language.Parser]::ParseInput($Function_Contents, [ref]$null, [ref]$null)
    }

    Context 'Prohibited Parameters' {
        It ('<FunctionName> does not have prohibited parameter: <ParameterName>') -Foreach $OrgUnit_Prohibited_Parameters {
            $Required_Parameter_Check = $Function_AST.ParamBlock.Parameters | Where-Object { $_.Name.Extent.Text -eq ('${0}' -f $ParameterName) }
            $Required_Parameter_Check | Should -BeNullOrEmpty
        }
    }
}

# Ensure that Find and Get functions have Properties and alias Property.
Describe 'Required Parameters Validation for Find or Get Function: <FunctionName>' -Tags @('Module', 'Unit') -ForEach $Required_Parameters_FindGet_Functions {
    BeforeAll {
        $Function_Contents = Get-Content -Path function:$FunctionName
        $Function_AST = [System.Management.Automation.Language.Parser]::ParseInput($Function_Contents, [ref]$null, [ref]$null)
    }

    Context 'Required Parameters' {
        It ('<FunctionName> has required parameter: <ParameterName>') -Foreach $Required_Parameters_FindGet {
            $Required_Parameter_Check = $Function_AST.ParamBlock.Parameters | Where-Object { $_.Name.Extent.Text -eq ('${0}' -f $ParameterName) }
            $Required_Parameter_Check | Should -Not -BeNullOrEmpty
        }
        It ('<FunctionName> has required alias: <Alias>') -Foreach $Required_Parameters_FindGet {
            $Required_Parameter_Check = $Function_AST.ParamBlock.Parameters | Where-Object { $_.Name.Extent.Text -eq ('${0}' -f $ParameterName) }
            $Required_Alias_Check = $Required_Parameter_Check | Where-Object { $_.Attributes.PositionalArguments.Value -eq $Alias }
            $Required_Alias_Check | Should -Not -BeNullOrEmpty
        }
    }
}

# Describe 'Function Validation' -Tags 'Module' {
#     $Module_Root = Split-Path -Path $PSScriptRoot -Parent
#     $Module_Path = Get-ChildItem -Path $Module_Root -Filter '*.psd1'
#     $Module_Information = Import-Module -Name $Module_Path.PSPath -Force -ErrorAction 'Stop' -PassThru
#     $Module_ExportedFunctions = $Module_Information.ExportedFunctions.Values.Name

#     [System.Collections.ArrayList]$TestCases = @()
#     $Module_ExportedFunctions | ForEach-Object {
#         [void]$TestCases.Add(@{FunctionName = $_})
#     }

#     BeforeEach {
#         $Function_Contents = Get-Content -Path function:$FunctionName
#         $Function_AST = [System.Management.Automation.Language.Parser]::ParseInput($Function_Contents, [ref]$null, [ref]$null)
#     }



#     # All Get-XXX and Find-XXX functions must have a Properties parameter, with a Property alias for that parameter.
#     Context 'Function Parameters - Get and Find functions have a Properties parameter and Property Alias' {
#         $TestCases = $TestCases | Where-Object { ($_.FunctionName -match '^Find|^Get') -and ($_.FunctionName -ne 'Get-DSSRootDSE') }

#         It '<FunctionName> has a Properties parameter' -TestCases $TestCases {
#             $Function_ParameterNames = $Function_AST.ParamBlock.Parameters.Name.VariablePath.UserPath
#             $Function_ParameterNames -contains 'Properties' | Should -Be $true
#         }
#         It '<FunctionName> has a Property alias to Properties parameter' -TestCases $TestCases {
#             $Properties_Parameter = $Function_AST.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Properties' }
#             $Properties_Alias_Attribute = $Properties_Parameter.Attributes | Where-Object { $_.TypeName.FullName -eq 'Alias' }
#             $Properties_Alias_Attribute.PositionalArguments.Value -eq 'Property' | Should -Be $true
#         }
#     }


# }
