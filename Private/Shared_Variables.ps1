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

# The Microsoft AD cmdlets also add a number of other useful properties based on calculations of other properties.
# Like creating a datetime object from an integer property.
# - LDAP property first, Microsoft alias(es) second.
$Useful_Calculated_Properties = @{
    # Delegation properties
    'msds-allowedtoactonbehalfofotheridentity' = 'principalsallowedtodelegatetoaccount'

    # Domain properties
    'gplink'                                   = 'linkedgrouppolicyobjects'
    'msds-optionalfeatureflags'                = 'featurescope'
    'msds-requireddomainbehaviorversion'       = 'requireddomainmode'
    'msds-requiredforestbehaviorversion'       = 'requiredforestmode'

    # Encryption properties
    'msds-supportedencryptiontypes'            = @('compoundidentitysupported', 'kerberosencryptiontype')

    # Group properties
    'grouptype'                                = @('groupcategory', 'groupscope')
    'primarygroupid'                           = 'primarygroup'

    # Security properties
    'ntsecuritydescriptor'                     = @('cannotchangepassword', 'protectedfromaccidentaldeletion')

    # Time properties (convert to FileTime)
    'accountexpires'                           = 'accountexpirationdate'
    'badpasswordtime'                          = 'lastbadpasswordattempt'
    'lastlogontimestamp'                       = 'lastlogondate'
    'lockouttime'                              = 'accountlockouttime'
    'pwdlastset'                               = 'passwordlastset'

    # Properties which are returned as TimeSpan objects, based on an integer stored in Active Directory.
    'msds-logontimesyncinterval'               = 'lastlogonreplicationinterval'
}

$Combined_Calculated_Properties = $Microsoft_Alias_Properties + $Useful_Calculated_Properties

# Like $Useful_Calculated_Properties, these are also calculated based on another property, but require some additional calculation on the sub-property as well.
$Useful_Calculated_SubProperties = @{
    # A number of properties returned by the AD Cmdlets are calculated based on flags to one of the UserAccountControl LDAP properties.
    # The list of flags and their corresponding values are taken from here:
    # - https://support.microsoft.com/en-us/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro
    'useraccountcontrol'                 = @{
        'accountnotdelegated'               = '0x0100000'
        'allowreversiblepasswordencryption' = '0x0000080'
        'doesnotrequirepreauth'             = '0x0400000'
        'enabled'                           = '0x0000002'
        'homedirrequired'                   = '0x0000008'
        'mnslogonaccount'                   = '0x0020000'
        'passwordneverexpires'              = '0x0010000'
        'passwordnotrequired'               = '0x0000020'
        'smartcardlogonrequired'            = '0x0040000'
        'trustedfordelegation'              = '0x0080000'
        'trustedtoauthfordelegation'        = '0x1000000'
        'usedeskeyonly'                     = '0x0200000'
    }
    'msds-user-account-control-computed' = @{
        'lockedout'       = '0x0000010'
        'passwordexpired' = '0x0800000'
    }

    # Get-ADDomain provides a number of "Container" properties which are calculated from the WellknownObjects or OtherWellknownObjects properties.
    # - Values taken from https://support.microsoft.com/en-gb/help/324949/redirecting-the-users-and-computers-containers-in-active-directory-dom
    'wellknownobjects'                   = @{
        'computerscontainer'                 = 'B:32:AA312825768811D1ADED00C04FD8D5CD:'
        'deletedobjectscontainer'            = 'B:32:18E2EA80684F11D2B9AA00C04F79F805:'
        'domaincontrollerscontainer'         = 'B:32:A361B2FFFFD211D1AA4B00C04FD7D83A:'
        'foreignsecurityprincipalscontainer' = 'B:32:22B70C67D56E4EFB91E9300FCA3DC1AA:'
        'infrastructurecontainer'            = 'B:32:2FBAC1870ADE11D297C400C04FD8D5CD:'
        'lostandfoundcontainer'              = 'B:32:AB8153B7768811D1ADED00C04FD8D5CD:'
        'microsoftprogramdatacontainer'      = 'B:32:F4BE92A4C777485E878E9421D53087DB:'
        'programdatacontainer'               = 'B:32:09460C08AE1E4A4EA0F64AEE7DAA1E5A:'
        'quotascontainer'                    = 'B:32:6227F0AF1FC2410D8E3BB10615BB5B0F:'
        'systemscontainer'                   = 'B:32:AB1D30F3768811D1ADED00C04FD8D5CD:'
        'userscontainer'                     = 'B:32:A9D1CA15768811D1ADED00C04FD8D5CD:'
    }
    'otherwellknownobjects'              = @{
        'keyscontainer'                   = 'B:32:683A24E2E8164BD3AF86AC3C2CF3F981:'
        'managedserviceaccountscontainer' = 'B:32:1EB93889E40C45DF9F0C64D23BBB6237:'
    }

    # These are calculated from the 'pwdproperties' property.
    # - Values taken from: https://docs.microsoft.com/en-us/windows/desktop/adschema/a-pwdproperties
    'pwdproperties'                      = @{
        'complexityenabled'           = '0x01'
        'reversibleencryptionenabled' = '0x10'
    }
}

# A set of arguments/properties to Set-ADUser which simply set a different LDAP property.
$Set_Alias_Properties = @{
    'pwdlastset' = 'changepasswordatlogon'
}

# A list of all the 2-letter country codes.
$Country_Codes = New-Object 'System.Collections.Generic.List[string]'
foreach ($Culture in [System.Globalization.CultureInfo]::GetCultures([System.Globalization.CultureTypes]::SpecificCultures)) {
    $TwoLetterCode = (New-Object 'System.Globalization.RegionInfo' -ArgumentList $Culture.Name).TwoLetterISORegionName
    if (($Country_Codes -notcontains $TwoLetterCode) -and ($TwoLetterCode -match '[A-Z]{2}')) {
        $Country_Codes.Add($TwoLetterCode)
    }
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
