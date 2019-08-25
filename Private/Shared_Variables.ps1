# A number of shared variables

# A list of all common function parameters
$All_CommonParameters = [System.Management.Automation.PSCmdlet]::CommonParameters + [System.Management.Automation.PSCmdlet]::OptionalCommonParameters

# The Microsoft AD Cmdlets add a number of "user-friendly" property names which are simply aliases of existing LDAP properties.
# - LDAP property first, Microsoft alias(es) second.
$Microsoft_Alias_Properties = @{
    'badpwdcount'                  = 'badlogoncount'
    'distinguishedname'            = 'computerobjectdn'
    'c'                            = 'country'
    'dnshostname'                  = 'hostname'
    'facsimiletelephonenumber'     = 'fax'
    'isdeleted'                    = 'deleted'
    'l'                            = 'city'
    'mail'                         = 'emailaddress'
    'maxpwdage'                    = 'maxpasswordage'
    'member'                       = 'members'
    'middlename'                   = 'othername'
    'minpwdage'                    = 'minpasswordage'
    'minpwdlength'                 = 'minpasswordlength'
    'mobile'                       = 'mobilephone'
    'msds-alloweddnssuffixes'      = 'alloweddnssuffixes'
    'msds-assignedauthnpolicy'     = 'authenticationpolicy'
    'msds-assignedauthnpolicysilo' = 'authenticationpolicysilo'
    'msds-hostserviceaccount'      = 'serviceaccount'
    'msds-optionalfeatureguid'     = 'featureguid'
    'msds-spnsuffixes'             = 'spnsuffixes'
    'o'                            = 'organization'
    'objectsid'                    = @('sid', 'domainsid')
    'physicaldeliveryofficename'   = 'office'
    'postofficebox'                = 'pobox'
    'pwdhistorylength'             = 'passwordhistorycount'
    'serviceprincipalname'         = 'serviceprincipalnames'
    'sn'                           = 'surname'
    'st'                           = 'state'
    'street'                       = 'streetaddress'
    'subrefs'                      = 'subordinatereferences'
    'telephonenumber'              = 'officephone'
    'usercertificate'              = 'certificates'
    'userworkstations'             = 'logonworkstations'
    'whenchanged'                  = @('modified', 'modifytimestamp')
    'whencreated'                  = @('created', 'createtimestamp')
    'wwwhomepage'                  = 'homepage'
}

# An Enum to determine KerberosEncryptionType.
# Taken from https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919
Add-Type -TypeDefinition @"
    [System.Flags]
    public enum ADKerberosEncryptionType {
        DES_CRC = 0x01,
        DES_MD5 = 0x02,
        RC4     = 0x04,
        AES128  = 0x08,
        AES256  = 0x10
    }
"@

# As of February 2019 there are only 2 OptionalFeatures available (Recycle Bin and Privileged Access Management) and both are Forest-wide in scope.
# Therefore the below table is a guess based on values taken from Enable-ADOptionalFeature - https://docs.microsoft.com/en-us/powershell/module/addsadministration/enable-adoptionalfeature
# Optional Features detailed here: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9ae2a9ad-970c-4938-a6bf-9c1fdc0b8b3e
$OptionalFeature_Scope_Table = @{
    '0' = 'Domain'
    '1' = 'ForestOrConfigurationSet'
}
