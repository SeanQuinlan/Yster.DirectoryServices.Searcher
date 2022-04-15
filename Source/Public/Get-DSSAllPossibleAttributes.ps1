function Get-DSSAllPossibleAttributes {
    <#
    .SYNOPSIS
        Gets all possible Active Directory attributes for an object class.
    .DESCRIPTION
        Query the Active Directory schema and return all the possible attributes for the specified object class.

        This function is not used by any other functions, but can be useful to easily list all attributes for a class.
    .EXAMPLE
        Get-DSSAllPossibleAttributes -ClassName 'user'

        Returns a list of all possible LDAP attributes for the user class.
    .NOTES
        References:
        https://www.easy365manager.com/how-to-get-all-active-directory-user-object-attributes/
        https://neroblanco.co.uk/2017/09/get-possible-ad-attributes-user-group/
    #>

    [CmdletBinding()]
    param(
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

        # The name of the class to get attributes for.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias('Class', 'ObjectClass', 'ObjectType')]
        [String]
        $ClassName,

        # The server or domain to connect to.
        # See below for some examples:
        #
        # -Server DC01
        # -Server 'dc01.contoso.com'
        # -Server CONTOSO
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Server
    )

    $Function_Name = (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Name
    $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Verbose ('{0}|Arguments: {1} - {2}' -f $Function_Name, $_.Key, ($_.Value -join ' ')) }

    try {
        $Basic_Parameters = @('Credential', 'Server')
        $Basic_Search_Parameters = @{}
        foreach ($Parameter in $Basic_Parameters) {
            if ($PSBoundParameters.ContainsKey($Parameter)) {
                Write-Verbose ('{0}|Adding Basic Search Parameter: {1} - {2}' -f $Function_Name, $Parameter, $PSBoundParameters[$Parameter])
                $Basic_Search_Parameters[$Parameter] = $PSBoundParameters[$Parameter]
            }
        }

        Write-Verbose ('{0}|Calling Get-DSSRootDSE' -f $Function_Name)
        $DSE_Return_Object = Get-DSSRootDSE @Basic_Search_Parameters

        $Class_Properties = @('maycontain', 'mustcontain', 'systemmaycontain', 'systemmustcontain')
        $Classes = while (-not $Exit_Loop) {
            $Class_Parameters = $Basic_Search_Parameters.PSBase.Clone()
            $Class_Parameters['SearchBase'] = $DSE_Return_Object.'schemanamingcontext'
            $Class_Parameters['LDAPFilter'] = '(ldapdisplayname={0})' -f $ClassName
            $Class_Parameters['Properties'] = $Class_Properties + @('auxiliaryclass', 'systemauxiliaryclass', 'subclassof', 'ldapdisplayname')
            $Class_Parameters['NoDefaultProperties'] = $true

            Write-Verbose ('{0}|Getting properties for class: {1}' -f $Function_Name, $ClassName)
            $Class_Details = Find-DSSObject @Class_Parameters
            if (-not $Class_Details) {
                $Terminating_ErrorRecord_Parameters = @{
                    'Exception'      = 'System.DirectoryServices.ActiveDirectory.ActiveDirectoryOperationException'
                    'ID'             = 'DSS-{0}' -f $Function_Name
                    'Category'       = 'InvalidData'
                    'TargetObject'   = $ClassName
                    'Message'        = 'Unable to find a match for class: {0}' -f $ClassName
                    'InnerException' = $_.Exception
                }
                $Terminating_ErrorRecord = New-ErrorRecord @Terminating_ErrorRecord_Parameters
                $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
            }
            if ($ClassName -eq $Class_Details.'subclassof') {
                $Exit_Loop = $true
            }
            $ClassName = $Class_Details.'subclassof'
            $Class_Details
        }

        $All_Class_Properties = New-Object -TypeName 'System.Collections.Generic.List[Object]'
        foreach ($Class in $Classes) {
            foreach ($Class_Property in $Class_Properties) {
                $All_Class_Properties.AddRange(@($Class.$Class_Property))
            }
            foreach ($Aux_Class in @('auxiliaryclass', 'systemauxiliaryclass')) {
                if ($Class.$Aux_Class) {
                    $Class.$Aux_Class | ForEach-Object {
                        $Aux_Class_Parameters = @{
                            'SearchBase'          = $DSE_Return_Object.'schemanamingcontext'
                            'LDAPFilter'          = '(ldapdisplayname={0})' -f $_
                            'Properties'          = $Class_Properties
                            'NoDefaultProperties' = $true
                        }
                        Write-Verbose ('{0}|Getting properties for auxiliary class: {1}' -f $Function_Name, $_)
                        $Aux_Class_Details = Find-DSSObject @Aux_Class_Parameters
                        foreach ($Class_Property in $Class_Properties) {
                            $All_Class_Properties.AddRange(@($Aux_Class_Details.$Class_Property))
                        }
                    }
                }
            }
        }
        $All_Class_Properties = $All_Class_Properties | Where-Object { $_ } | Sort-Object -Unique
        Write-Verbose ('{0}|Found {1} properties for class: {2}' -f $Function_Name, $All_Class_Properties.Count, $ClassName)
        $All_Class_Properties

    } catch {
        if ($_.FullyQualifiedErrorId -match '^DSS-') {
            $Terminating_ErrorRecord = New-DefaultErrorRecord -InputObject $_
            $PSCmdlet.ThrowTerminatingError($Terminating_ErrorRecord)
        } else {
            throw
        }
    }
}
