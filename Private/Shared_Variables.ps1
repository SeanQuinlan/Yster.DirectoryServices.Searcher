# A number of shared variables

# A list of all common function parameters
$All_CommonParameters = [System.Management.Automation.PSCmdlet]::CommonParameters + [System.Management.Automation.PSCmdlet]::OptionalCommonParameters

# The Microsoft AD Cmdlets add a number of "user-friendly" property names which are simply aliases of existing LDAP properties.
# - LDAP property first, AD alias(es) second.
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
    'office'                       = 'physicaldeliveryofficename'
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
