$Module_Root = Split-Path -Path $PSScriptRoot -Parent
$Module_Path = Get-ChildItem -Path $Module_Root -Filter '*.psd1'
$Module_Name = $Module_Path | Select-Object -ExpandProperty 'BaseName'

$Module_Information = Import-Module -Name $Module_Path.PSPath -Force -ErrorAction 'Stop' -PassThru
$Module_ExportedFunctions = $Module_Information.ExportedFunctions.Values.Name

Describe ('{0} Function Validation' -f $Module_Name) -Tags 'Module' {
    foreach ($Function in $Module_ExportedFunctions) {
        $Function_Contents = Get-Content -Path function:$Function
        $Function_AST = [System.Management.Automation.Language.Parser]::ParseInput($Function_Contents, [ref]$null, [ref]$null)

        Context ('Function: {0}' -f $Function) {
            It 'Help - Has Synopsis' {
                $Function_AST.GetHelpContent().Synopsis | Should Not BeNullOrEmpty
            }

            It 'Help - Has Description' {
                $Function_AST.GetHelpContent().Description | Should Not BeNullOrEmpty
            }

            It 'Help - Has at least 1 Code example' {
                $Function_AST.GetHelpContent().Examples.Count | Should BeGreaterThan 0
            }

            # Insipired from: https://lazywinadmin.com/2016/08/powershellpester-make-sure-your-comment.html
            $null = $Function_Contents -match '(?ms)\s+\<\#.*\>\#?'
            $Function_CommentsNotIndented = $matches[0].Split("`n") -notmatch '^[\t|\s{4}]'
            It 'Help - Comment block is indented' {
                $Function_CommentsNotIndented.Count | Should Be 0
            }

            # Inspired from: https://lazywinadmin.com/2016/08/powershellpester-make-sure-your.html
            $Function_ParamBlock = $Function_AST.ParamBlock.Extent.Text.Split("`n").Trim()
            $Function_ParameterNames = $Function_AST.ParamBlock.Parameters.Name.VariablePath.UserPath
            $Function_ParameterBlocks = $Function_ParameterNames | Where-Object {
                $Function_AST.ParamBlock.Extent.Text -match ('{0}.*,' -f $_) # Only match those with a comma after the parameter (ie. exclude the last parameter).
            }
            foreach ($ParameterName in $Function_ParameterBlocks) {
                # Select-String's LineNumber properties start from 1 since they are designed to be output to the console.
                # This is useful because it effectively gets the line "after" the match, which is the line we want to check is a blank line.
                $Function_Param_LineNumber = $Function_ParamBlock | Select-String ('{0}.*,$' -f $ParameterName) | Select-Object -ExpandProperty LineNumber
                It ('Parameter is followed by a blank line: {0}' -f $ParameterName) {
                    [String]::IsNullOrWhiteSpace($Function_ParamBlock[$Function_Param_LineNumber]) | Should Be $true
                }
            }

            # Any function ending in Object should not have SAMAccountName or ObjectSID parameters.
            if ($Function -match 'Object$') {
                It 'Does not have ObjectSID or SAMAccountName parameters' {
                    ($Function_ParameterNames -notcontains 'ObjectSID') -and ($Function_ParameterNames -notcontains 'SAMAccountName') | Should Be $true
                }
            }
        }
    }
}
