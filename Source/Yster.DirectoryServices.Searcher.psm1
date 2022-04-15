$Public_Folder = 'Public'
$Private_Folder = 'Private'
$ScriptRoot = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Definition)

foreach ($Function_Folder in @($Public_Folder, $Private_Folder)) {
    $Functions_To_Import = @( Get-ChildItem -Path (Join-Path -Path $ScriptRoot -ChildPath $Function_Folder) -Filter '*.ps1' -ErrorAction SilentlyContinue )
    if ($Functions_To_Import) {
        if ($Function_Folder -eq $Public_Folder) {
            $Public_Functions = $Functions_To_Import | Select-Object -ExpandProperty 'BaseName'
        }
        foreach ($Function in $Functions_To_Import) {
            try {
                . ([ScriptBlock]::Create([System.IO.File]::ReadAllText($Function.FullName)))
            } catch {
                Write-Error ('Error importing function "{0}": {1}' -f $Function.FullName, $_.Exception.Message)
            }
        }
    }
}

# Export only the public functions
Export-ModuleMember -Function $Public_Functions
