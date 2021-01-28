# Some helpful links:
# https://stackoverflow.com/questions/62497134/pester-5-0-2-beforeall-block-code-not-showing-up-in-describe-block


Describe 'Function Validation' -Tags 'Module' {
    $Module_Root = Split-Path -Path $PSScriptRoot -Parent
    $Module_Path = Get-ChildItem -Path $Module_Root -Filter '*.psd1'
    $Module_Information = Import-Module -Name $Module_Path.PSPath -Force -ErrorAction 'Stop' -PassThru
    $Module_ExportedFunctions = $Module_Information.ExportedFunctions.Values.Name

    [System.Collections.ArrayList]$TestCases = @()
    $Module_ExportedFunctions | ForEach-Object {
        [void]$TestCases.Add(@{FunctionName = $_})
    }

    BeforeEach {
        $Function_Contents = Get-Content -Path function:$FunctionName
        $Function_AST = [System.Management.Automation.Language.Parser]::ParseInput($Function_Contents, [ref]$null, [ref]$null)
    }

    Context 'Function Help - has Synopsis' {
        It '<FunctionName> has Synopsis' -TestCases $TestCases {
            $Function_AST.GetHelpContent().Synopsis | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Function Help - has Description' {
        It '<FunctionName> has Description' -TestCases $TestCases {
            $Function_AST.GetHelpContent().Description | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Function Help - has at least 1 Code example' {
        It '<FunctionName> has at least 1 Code example' -TestCases $TestCases {
            $Function_AST.GetHelpContent().Examples.Count | Should -BeGreaterThan 0
        }
    }

    # Insipired from: https://lazywinadmin.com/2016/08/powershellpester-make-sure-your-comment.html
    Context 'Function Help - Comment block is indented' {
        It '<FunctionName> has indented comment block' -TestCases $TestCases {
            $null = $Function_Contents -match '(?ms)\s+\<\#.*\>\#?'
            $Function_CommentsNotIndented = $matches[0].Split("`n") -notmatch '^[\t|\s{4}]'
            $Function_CommentsNotIndented.Count | Should -Be 0        }
    }

    # Any function ending in Object or OrganizationalUnit should not have SAMAccountName parameter.
    Context 'Function Parameters - No SAMAccountName for Object or OrganizationalUnit' {
        $TestCases = $TestCases | Where-Object { $_.FunctionName -match 'Object$|OrganizationalUnit$' }
        It '<FunctionName> does not have SAMAccountName parameter' -TestCases $TestCases {
            $Function_ParameterNames = $Function_AST.ParamBlock.Parameters.Name.VariablePath.UserPath
            $Function_ParameterNames -notcontains 'SAMAccountName' | Should -Be $true
        }
    }

    # OrganizationalUnits do not have SIDs, so ensure that no relevant function has that as a parameter.
    Context 'Function Parameters - No ObjectSID parameter for OrganizationalUnit functions' {
        $TestCases = $TestCases | Where-Object { $_.FunctionName -match 'OrganizationalUnit$' }
        It '<FunctionName> does not have ObjectSID parameter' -TestCases $TestCases {
            $Function_ParameterNames = $Function_AST.ParamBlock.Parameters.Name.VariablePath.UserPath
            $Function_ParameterNames -notcontains 'ObjectSID' | Should -Be $true
        }
    }

    # All Public functions should have the common parameters.
    Context 'Function Parameters - Public functions have common parameters' {
        $Public_Common_Parameters_Exclude_Context = @('Get-DSSDomain', 'Get-DSSForest', 'Get-DSSRootDSE')

        It '<FunctionName> has Credential parameter' -TestCases $TestCases {
            $Function_ParameterNames = $Function_AST.ParamBlock.Parameters.Name.VariablePath.UserPath
            $Function_ParameterNames -contains 'Credential' | Should -Be $true
        }
        It '<FunctionName> has Server parameter' -TestCases $TestCases {
            $Function_ParameterNames = $Function_AST.ParamBlock.Parameters.Name.VariablePath.UserPath
            $Function_ParameterNames -contains 'Server' | Should -Be $true
        }
        It '<FunctionName> has Context parameter' -TestCases ($TestCases | Where-Object { $Public_Common_Parameters_Exclude_Context -notcontains $_.FunctionName }) {
            $Function_ParameterNames = $Function_AST.ParamBlock.Parameters.Name.VariablePath.UserPath
            $Function_ParameterNames -contains 'Context' | Should -Be $true
        }
    }

    # All Find-XXX functions must have a PageSize parameter
    Context 'Function Parameters - Find functions have a PageSize parameter' {
        $TestCases = $TestCases | Where-Object { $_.FunctionName -match '^Find' }
        It '<FunctionName> has a PageSize parameter' -TestCases $TestCases {
            $Function_ParameterNames = $Function_AST.ParamBlock.Parameters.Name.VariablePath.UserPath
            $Function_ParameterNames -contains 'PageSize' | Should -Be $true
        }
    }

    # Inspired from: https://lazywinadmin.com/2016/08/powershellpester-make-sure-your.html
    Context 'Function has parameters separated by blank line' {
        It '<FunctionName> parameters separated by blank lines' -TestCases $TestCases {
            $Function_ParamBlock = $Function_AST.ParamBlock.Extent.Text.Split("`n").Trim()
            $Function_ParameterNames = $Function_AST.ParamBlock.Parameters.Name.VariablePath.UserPath
            $Function_ParameterBlocks = $Function_ParameterNames | Where-Object {
                $Function_AST.ParamBlock.Extent.Text -match ('\${0}.*,' -f $_) # Only match those with a comma after the parameter (ie. exclude the last parameter).
            }

            foreach ($ParameterName in $Function_ParameterBlocks) {
                # Select-String's LineNumber properties start from 1 since they are designed to be output to the console.
                # This is useful because it effectively gets the line "after" the match, which is the line we want to check is a blank line.
                $Function_Param_LineNumber = $Function_ParamBlock | Select-String ('{0}.*,$' -f $ParameterName) | Select-Object -ExpandProperty LineNumber
                [String]::IsNullOrWhiteSpace($Function_ParamBlock[$Function_Param_LineNumber]) | Should -Be $true
            }
        }
    }

}
