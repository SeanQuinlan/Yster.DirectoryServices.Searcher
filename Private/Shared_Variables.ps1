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
    'msds-supportedencryptiontypes' = 'kerberosencryptiontype'
    'ntsecuritydescriptor'          = 'cannotchangepassword'
    'pwdlastset'                    = 'changepasswordatlogon'
}

# An Enum to determine KerberosEncryptionType.
# Taken from https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919
Add-Type -TypeDefinition @"
    [System.Flags]
    public enum ADKerberosEncryptionType {
        None    = 0x00,
        DES_CRC = 0x01,
        DES_MD5 = 0x02,
        RC4     = 0x04,
        AES128  = 0x08,
        AES256  = 0x10
    }
"@

# Some additional flags to the 'msds-supportedencryptiontypes' property which don't form part of the ADKerberosEncryptionType Enum.
# - Taken from https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919
$Additional_Encryption_Types = @{
    'FAST-Supported'                    = '0x10000'
    'Compound-Identity-Supported'       = '0x20000'
    'Claims-Supported'                  = '0x40000'
    'Resource-SID-Compression-Disabled' = '0x80000'
}

# As of February 2019 there are only 2 OptionalFeatures available (Recycle Bin and Privileged Access Management) and both are Forest-wide in scope.
# Therefore the below table is a guess based on values taken from Enable-ADOptionalFeature - https://docs.microsoft.com/en-us/powershell/module/addsadministration/enable-adoptionalfeature
# Optional Features detailed here: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9ae2a9ad-970c-4938-a6bf-9c1fdc0b8b3e
$OptionalFeature_Scope_Table = @{
    '0' = 'Domain'
    '1' = 'ForestOrConfigurationSet'
}

# Variables related to the "Cannot Change Password" properties.
# Adapted from: https://social.technet.microsoft.com/Forums/scriptcenter/en-US/e947d590-d183-46b9-9a7a-4e785638c6fb/how-can-i-get-a-list-of-active-directory-user-accounts-where-the-user-cannot-change-the-password?forum=ITCG
$ChangePassword_GUID = 'ab721a53-1e2f-11d0-9819-00aa0040529b'
$ChangePassword_Identity_Everyone_SID = New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList ([System.Security.Principal.WellKnownSidType]::WorldSid, $null) # Everyone
$ChangePassword_Identity_Everyone_Object = $ChangePassword_Identity_Everyone_SID.Translate([System.Security.Principal.NTAccount])
$ChangePassword_Identity_Self_SID = New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList ([System.Security.Principal.WellKnownSidType]::SelfSid, $null) # NT AUTHORITY\SELF
$ChangePassword_Identity_Self_Object = $ChangePassword_Identity_Self_SID.Translate([System.Security.Principal.NTAccount])

# Active Directory country names and codes.
# Taken from the Bia.Countries module - https://github.com/lehtoj/Bia.Countries
$Countries = @{
    "Afghanistan"                                  = @{
        'Alpha2'      = 'AF'
        'CountryCode' = '4'
    }
    "Åland Islands"                                = @{
        'Alpha2'      = 'AX'
        'CountryCode' = '248'
    }
    "Albania"                                      = @{
        'Alpha2'      = 'AL'
        'CountryCode' = '8'
    }
    "Algeria"                                      = @{
        'Alpha2'      = 'DZ'
        'CountryCode' = '12'
    }
    "American Samoa"                               = @{
        'Alpha2'      = 'AS'
        'CountryCode' = '16'
    }
    "Andorra"                                      = @{
        'Alpha2'      = 'AD'
        'CountryCode' = '20'
    }
    "Angola"                                       = @{
        'Alpha2'      = 'AO'
        'CountryCode' = '24'
    }
    "Anguilla"                                     = @{
        'Alpha2'      = 'AI'
        'CountryCode' = '660'
    }
    "Antarctica"                                   = @{
        'Alpha2'      = 'AQ'
        'CountryCode' = '10'
    }
    "Antigua and Barbuda"                          = @{
        'Alpha2'      = 'AG'
        'CountryCode' = '28'
    }
    "Argentina"                                    = @{
        'Alpha2'      = 'AR'
        'CountryCode' = '32'
    }
    "Armenia"                                      = @{
        'Alpha2'      = 'AM'
        'CountryCode' = '51'
    }
    "Aruba"                                        = @{
        'Alpha2'      = 'AW'
        'CountryCode' = '533'
    }
    "Australia"                                    = @{
        'Alpha2'      = 'AU'
        'CountryCode' = '36'
    }
    "Austria"                                      = @{
        'Alpha2'      = 'AT'
        'CountryCode' = '40'
    }
    "Azerbaijan"                                   = @{
        'Alpha2'      = 'AZ'
        'CountryCode' = '31'
    }
    "Bahamas, The"                                 = @{
        'Alpha2'      = 'BS'
        'CountryCode' = '44'
    }
    "Bahrain"                                      = @{
        'Alpha2'      = 'BH'
        'CountryCode' = '48'
    }
    "Baker Island"                                 = @{
        'Alpha2'      = 'XX'
        'CountryCode' = '581'
    }
    "Bangladesh"                                   = @{
        'Alpha2'      = 'BD'
        'CountryCode' = '50'
    }
    "Barbados"                                     = @{
        'Alpha2'      = 'BB'
        'CountryCode' = '52'
    }
    "Belarus"                                      = @{
        'Alpha2'      = 'BY'
        'CountryCode' = '112'
    }
    "Belgium"                                      = @{
        'Alpha2'      = 'BE'
        'CountryCode' = '56'
    }
    "Belize"                                       = @{
        'Alpha2'      = 'BZ'
        'CountryCode' = '84'
    }
    "Benin"                                        = @{
        'Alpha2'      = 'BJ'
        'CountryCode' = '204'
    }
    "Bermuda"                                      = @{
        'Alpha2'      = 'BM'
        'CountryCode' = '60'
    }
    "Bhutan"                                       = @{
        'Alpha2'      = 'BT'
        'CountryCode' = '64'
    }
    "Bolivia"                                      = @{
        'Alpha2'      = 'BO'
        'CountryCode' = '68'
    }
    "Bonaire, Sint Eustatius and Saba"             = @{
        'Alpha2'      = 'BQ'
        'CountryCode' = '535'
    }
    "Bosnia and Herzegovina"                       = @{
        'Alpha2'      = 'BA'
        'CountryCode' = '70'
    }
    "Botswana"                                     = @{
        'Alpha2'      = 'BW'
        'CountryCode' = '72'
    }
    "Bouvet Island"                                = @{
        'Alpha2'      = 'BV'
        'CountryCode' = '74'
    }
    "Brazil"                                       = @{
        'Alpha2'      = 'BR'
        'CountryCode' = '76'
    }
    "British Indian Ocean Territory"               = @{
        'Alpha2'      = 'IO'
        'CountryCode' = '86'
    }
    "Brunei"                                       = @{
        'Alpha2'      = 'BN'
        'CountryCode' = '96'
    }
    "Bulgaria"                                     = @{
        'Alpha2'      = 'BG'
        'CountryCode' = '100'
    }
    "Burkina Faso"                                 = @{
        'Alpha2'      = 'BF'
        'CountryCode' = '854'
    }
    "Burundi"                                      = @{
        'Alpha2'      = 'BI'
        'CountryCode' = '108'
    }
    "Cape Verde"                                   = @{
        'Alpha2'      = 'CV'
        'CountryCode' = '132'
    }
    "Cambodia"                                     = @{
        'Alpha2'      = 'KH'
        'CountryCode' = '116'
    }
    "Cameroon"                                     = @{
        'Alpha2'      = 'CM'
        'CountryCode' = '120'
    }
    "Canada"                                       = @{
        'Alpha2'      = 'CA'
        'CountryCode' = '124'
    }
    "Cayman Islands"                               = @{
        'Alpha2'      = 'KY'
        'CountryCode' = '136'
    }
    "Central African Republic"                     = @{
        'Alpha2'      = 'CF'
        'CountryCode' = '140'
    }
    "Chad"                                         = @{
        'Alpha2'      = 'TD'
        'CountryCode' = '148'
    }
    "Chile"                                        = @{
        'Alpha2'      = 'CL'
        'CountryCode' = '152'
    }
    "China"                                        = @{
        'Alpha2'      = 'CN'
        'CountryCode' = '156'
    }
    "Christmas Island"                             = @{
        'Alpha2'      = 'CX'
        'CountryCode' = '162'
    }
    "Cocos (Keeling) Islands"                      = @{
        'Alpha2'      = 'CC'
        'CountryCode' = '166'
    }
    "Colombia"                                     = @{
        'Alpha2'      = 'CO'
        'CountryCode' = '170'
    }
    "Comoros"                                      = @{
        'Alpha2'      = 'KM'
        'CountryCode' = '174'
    }
    "Congo (DRC)"                                  = @{
        'Alpha2'      = 'CD'
        'CountryCode' = '180'
    }
    "Congo"                                        = @{
        'Alpha2'      = 'CG'
        'CountryCode' = '178'
    }
    "Cook Islands"                                 = @{
        'Alpha2'      = 'CK'
        'CountryCode' = '184'
    }
    "Costa Rica"                                   = @{
        'Alpha2'      = 'CR'
        'CountryCode' = '188'
    }
    "Côte d'Ivoire"                                = @{
        'Alpha2'      = 'CI'
        'CountryCode' = '384'
    }
    "Croatia"                                      = @{
        'Alpha2'      = 'HR'
        'CountryCode' = '191'
    }
    "Cuba"                                         = @{
        'Alpha2'      = 'CU'
        'CountryCode' = '192'
    }
    "Curaçao"                                      = @{
        'Alpha2'      = 'CW'
        'CountryCode' = '531'
    }
    "Cyprus"                                       = @{
        'Alpha2'      = 'CY'
        'CountryCode' = '196'
    }
    "Czech Republic"                               = @{
        'Alpha2'      = 'CZ'
        'CountryCode' = '203'
    }
    "Denmark"                                      = @{
        'Alpha2'      = 'DK'
        'CountryCode' = '208'
    }
    "Djibouti"                                     = @{
        'Alpha2'      = 'DJ'
        'CountryCode' = '262'
    }
    "Dominica"                                     = @{
        'Alpha2'      = 'DM'
        'CountryCode' = '212'
    }
    "Dominican Republic"                           = @{
        'Alpha2'      = 'DO'
        'CountryCode' = '214'
    }
    "Ecuador"                                      = @{
        'Alpha2'      = 'EC'
        'CountryCode' = '218'
    }
    "Egypt"                                        = @{
        'Alpha2'      = 'EG'
        'CountryCode' = '818'
    }
    "El Salvador"                                  = @{
        'Alpha2'      = 'SV'
        'CountryCode' = '222'
    }
    "Equatorial Guinea"                            = @{
        'Alpha2'      = 'GQ'
        'CountryCode' = '226'
    }
    "Eritrea"                                      = @{
        'Alpha2'      = 'ER'
        'CountryCode' = '232'
    }
    "Estonia"                                      = @{
        'Alpha2'      = 'EE'
        'CountryCode' = '233'
    }
    "Ethiopia"                                     = @{
        'Alpha2'      = 'ET'
        'CountryCode' = '231'
    }
    "Falkland Islands (Islas Malvinas)"            = @{
        'Alpha2'      = 'FK'
        'CountryCode' = '238'
    }
    "Faroe Islands"                                = @{
        'Alpha2'      = 'FO'
        'CountryCode' = '234'
    }
    "Fiji Islands"                                 = @{
        'Alpha2'      = 'FJ'
        'CountryCode' = '242'
    }
    "Finland"                                      = @{
        'Alpha2'      = 'FI'
        'CountryCode' = '246'
    }
    "France"                                       = @{
        'Alpha2'      = 'FR'
        'CountryCode' = '250'
    }
    "French Guiana"                                = @{
        'Alpha2'      = 'GF'
        'CountryCode' = '254'
    }
    "French Polynesia"                             = @{
        'Alpha2'      = 'PF'
        'CountryCode' = '258'
    }
    "French Southern and Antarctic Lands"          = @{
        'Alpha2'      = 'TF'
        'CountryCode' = '260'
    }
    "Gabon"                                        = @{
        'Alpha2'      = 'GA'
        'CountryCode' = '266'
    }
    "Gambia, The"                                  = @{
        'Alpha2'      = 'GM'
        'CountryCode' = '270'
    }
    "Georgia"                                      = @{
        'Alpha2'      = 'GE'
        'CountryCode' = '268'
    }
    "Germany"                                      = @{
        'Alpha2'      = 'DE'
        'CountryCode' = '276'
    }
    "Ghana"                                        = @{
        'Alpha2'      = 'GH'
        'CountryCode' = '288'
    }
    "Gibraltar"                                    = @{
        'Alpha2'      = 'GI'
        'CountryCode' = '292'
    }
    "Greece"                                       = @{
        'Alpha2'      = 'GR'
        'CountryCode' = '300'
    }
    "Greenland"                                    = @{
        'Alpha2'      = 'GL'
        'CountryCode' = '304'
    }
    "Grenada"                                      = @{
        'Alpha2'      = 'GD'
        'CountryCode' = '308'
    }
    "Guadeloupe"                                   = @{
        'Alpha2'      = 'GP'
        'CountryCode' = '312'
    }
    "Guam"                                         = @{
        'Alpha2'      = 'GU'
        'CountryCode' = '316'
    }
    "Guatemala"                                    = @{
        'Alpha2'      = 'GT'
        'CountryCode' = '320'
    }
    "Guernsey"                                     = @{
        'Alpha2'      = 'GG'
        'CountryCode' = '831'
    }
    "Guinea"                                       = @{
        'Alpha2'      = 'GN'
        'CountryCode' = '324'
    }
    "Guinea-Bissau"                                = @{
        'Alpha2'      = 'GW'
        'CountryCode' = '624'
    }
    "Guyana"                                       = @{
        'Alpha2'      = 'GY'
        'CountryCode' = '328'
    }
    "Haiti"                                        = @{
        'Alpha2'      = 'HT'
        'CountryCode' = '332'
    }
    "Heard Island and McDonald Islands"            = @{
        'Alpha2'      = 'HM'
        'CountryCode' = '334'
    }
    "Vatican City"                                 = @{
        'Alpha2'      = 'VA'
        'CountryCode' = '336'
    }
    "Honduras"                                     = @{
        'Alpha2'      = 'HN'
        'CountryCode' = '340'
    }
    "Hong Kong SAR"                                = @{
        'Alpha2'      = 'HK'
        'CountryCode' = '344'
    }
    "Howland Island"                               = @{
        'Alpha2'      = 'XX'
        'CountryCode' = '581'
    }
    "Hungary"                                      = @{
        'Alpha2'      = 'HU'
        'CountryCode' = '348'
    }
    "Iceland"                                      = @{
        'Alpha2'      = 'IS'
        'CountryCode' = '352'
    }
    "India"                                        = @{
        'Alpha2'      = 'IN'
        'CountryCode' = '356'
    }
    "Indonesia"                                    = @{
        'Alpha2'      = 'ID'
        'CountryCode' = '360'
    }
    "Iran"                                         = @{
        'Alpha2'      = 'IR'
        'CountryCode' = '364'
    }
    "Iraq"                                         = @{
        'Alpha2'      = 'IQ'
        'CountryCode' = '368'
    }
    "Ireland"                                      = @{
        'Alpha2'      = 'IE'
        'CountryCode' = '372'
    }
    "Man, Isle of"                                 = @{
        'Alpha2'      = 'IM'
        'CountryCode' = '833'
    }
    "Israel"                                       = @{
        'Alpha2'      = 'IL'
        'CountryCode' = '376'
    }
    "Italy"                                        = @{
        'Alpha2'      = 'IT'
        'CountryCode' = '380'
    }
    "Jamaica"                                      = @{
        'Alpha2'      = 'JM'
        'CountryCode' = '388'
    }
    "Japan"                                        = @{
        'Alpha2'      = 'JP'
        'CountryCode' = '392'
    }
    "Jarvis Island"                                = @{
        'Alpha2'      = 'XX'
        'CountryCode' = '581'
    }
    "Jersey"                                       = @{
        'Alpha2'      = 'JE'
        'CountryCode' = '832'
    }
    "Johnston Atoll"                               = @{
        'Alpha2'      = 'XX'
        'CountryCode' = '581'
    }
    "Jordan"                                       = @{
        'Alpha2'      = 'JO'
        'CountryCode' = '400'
    }
    "Kazakhstan"                                   = @{
        'Alpha2'      = 'KZ'
        'CountryCode' = '398'
    }
    "Kenya"                                        = @{
        'Alpha2'      = 'KE'
        'CountryCode' = '404'
    }
    "Kingman Reef"                                 = @{
        'Alpha2'      = 'XX'
        'CountryCode' = '581'
    }
    "Kiribati"                                     = @{
        'Alpha2'      = 'KI'
        'CountryCode' = '296'
    }
    "North Korea"                                  = @{
        'Alpha2'      = 'KP'
        'CountryCode' = '408'
    }
    "Korea"                                        = @{
        'Alpha2'      = 'KR'
        'CountryCode' = '410'
    }
    "Kuwait"                                       = @{
        'Alpha2'      = 'KW'
        'CountryCode' = '414'
    }
    "Kyrgyzstan"                                   = @{
        'Alpha2'      = 'KG'
        'CountryCode' = '417'
    }
    "Laos"                                         = @{
        'Alpha2'      = 'LA'
        'CountryCode' = '418'
    }
    "Latvia"                                       = @{
        'Alpha2'      = 'LV'
        'CountryCode' = '428'
    }
    "Lebanon"                                      = @{
        'Alpha2'      = 'LB'
        'CountryCode' = '422'
    }
    "Lesotho"                                      = @{
        'Alpha2'      = 'LS'
        'CountryCode' = '426'
    }
    "Liberia"                                      = @{
        'Alpha2'      = 'LR'
        'CountryCode' = '430'
    }
    "Libya"                                        = @{
        'Alpha2'      = 'LY'
        'CountryCode' = '434'
    }
    "Liechtenstein"                                = @{
        'Alpha2'      = 'LI'
        'CountryCode' = '438'
    }
    "Lithuania"                                    = @{
        'Alpha2'      = 'LT'
        'CountryCode' = '440'
    }
    "Luxembourg"                                   = @{
        'Alpha2'      = 'LU'
        'CountryCode' = '442'
    }
    "Macao SAR"                                    = @{
        'Alpha2'      = 'MO'
        'CountryCode' = '446'
    }
    "Macedonia, Former Yugoslav Republic of"       = @{
        'Alpha2'      = 'MK'
        'CountryCode' = '807'
    }
    "Madagascar"                                   = @{
        'Alpha2'      = 'MG'
        'CountryCode' = '450'
    }
    "Malawi"                                       = @{
        'Alpha2'      = 'MW'
        'CountryCode' = '454'
    }
    "Malaysia"                                     = @{
        'Alpha2'      = 'MY'
        'CountryCode' = '458'
    }
    "Maldives"                                     = @{
        'Alpha2'      = 'MV'
        'CountryCode' = '462'
    }
    "Mali"                                         = @{
        'Alpha2'      = 'ML'
        'CountryCode' = '466'
    }
    "Malta"                                        = @{
        'Alpha2'      = 'MT'
        'CountryCode' = '470'
    }
    "Marshall Islands"                             = @{
        'Alpha2'      = 'MH'
        'CountryCode' = '584'
    }
    "Martinique"                                   = @{
        'Alpha2'      = 'MQ'
        'CountryCode' = '474'
    }
    "Mauritania"                                   = @{
        'Alpha2'      = 'MR'
        'CountryCode' = '478'
    }
    "Mauritius"                                    = @{
        'Alpha2'      = 'MU'
        'CountryCode' = '480'
    }
    "Mayotte"                                      = @{
        'Alpha2'      = 'YT'
        'CountryCode' = '175'
    }
    "Mexico"                                       = @{
        'Alpha2'      = 'MX'
        'CountryCode' = '484'
    }
    "Micronesia"                                   = @{
        'Alpha2'      = 'FM'
        'CountryCode' = '583'
    }
    "Midway Islands"                               = @{
        'Alpha2'      = 'XX'
        'CountryCode' = '581'
    }
    "Moldova"                                      = @{
        'Alpha2'      = 'MD'
        'CountryCode' = '498'
    }
    "Monaco"                                       = @{
        'Alpha2'      = 'MC'
        'CountryCode' = '492'
    }
    "Mongolia"                                     = @{
        'Alpha2'      = 'MN'
        'CountryCode' = '496'
    }
    "Montenegro"                                   = @{
        'Alpha2'      = 'ME'
        'CountryCode' = '499'
    }
    "Montserrat"                                   = @{
        'Alpha2'      = 'MS'
        'CountryCode' = '500'
    }
    "Morocco"                                      = @{
        'Alpha2'      = 'MA'
        'CountryCode' = '504'
    }
    "Mozambique"                                   = @{
        'Alpha2'      = 'MZ'
        'CountryCode' = '508'
    }
    "Myanmar"                                      = @{
        'Alpha2'      = 'MM'
        'CountryCode' = '104'
    }
    "Namibia"                                      = @{
        'Alpha2'      = 'NA'
        'CountryCode' = '516'
    }
    "Nauru"                                        = @{
        'Alpha2'      = 'NR'
        'CountryCode' = '520'
    }
    "Nepal"                                        = @{
        'Alpha2'      = 'NP'
        'CountryCode' = '524'
    }
    "Netherlands"                                  = @{
        'Alpha2'      = 'NL'
        'CountryCode' = '528'
    }
    "New Caledonia"                                = @{
        'Alpha2'      = 'NC'
        'CountryCode' = '540'
    }
    "New Zealand"                                  = @{
        'Alpha2'      = 'NZ'
        'CountryCode' = '554'
    }
    "Nicaragua"                                    = @{
        'Alpha2'      = 'NI'
        'CountryCode' = '558'
    }
    "Niger"                                        = @{
        'Alpha2'      = 'NE'
        'CountryCode' = '562'
    }
    "Nigeria"                                      = @{
        'Alpha2'      = 'NG'
        'CountryCode' = '566'
    }
    "Niue"                                         = @{
        'Alpha2'      = 'NU'
        'CountryCode' = '570'
    }
    "Norfolk Island"                               = @{
        'Alpha2'      = 'NF'
        'CountryCode' = '574'
    }
    "Northern Mariana Islands"                     = @{
        'Alpha2'      = 'MP'
        'CountryCode' = '580'
    }
    "Norway"                                       = @{
        'Alpha2'      = 'NO'
        'CountryCode' = '578'
    }
    "Oman"                                         = @{
        'Alpha2'      = 'OM'
        'CountryCode' = '512'
    }
    "Pakistan"                                     = @{
        'Alpha2'      = 'PK'
        'CountryCode' = '586'
    }
    "Palau"                                        = @{
        'Alpha2'      = 'PW'
        'CountryCode' = '585'
    }
    "Palestinian Authority"                        = @{
        'Alpha2'      = 'PS'
        'CountryCode' = '275'
    }
    "Palmyra Atoll"                                = @{
        'Alpha2'      = 'XX'
        'CountryCode' = '581'
    }
    "Panama"                                       = @{
        'Alpha2'      = 'PA'
        'CountryCode' = '591'
    }
    "Papua New Guinea"                             = @{
        'Alpha2'      = 'PG'
        'CountryCode' = '598'
    }
    "Paraguay"                                     = @{
        'Alpha2'      = 'PY'
        'CountryCode' = '600'
    }
    "Peru"                                         = @{
        'Alpha2'      = 'PE'
        'CountryCode' = '604'
    }
    "Philippines"                                  = @{
        'Alpha2'      = 'PH'
        'CountryCode' = '608'
    }
    "Pitcairn Islands"                             = @{
        'Alpha2'      = 'PN'
        'CountryCode' = '612'
    }
    "Poland"                                       = @{
        'Alpha2'      = 'PL'
        'CountryCode' = '616'
    }
    "Portugal"                                     = @{
        'Alpha2'      = 'PT'
        'CountryCode' = '620'
    }
    "Puerto Rico"                                  = @{
        'Alpha2'      = 'PR'
        'CountryCode' = '630'
    }
    "Qatar"                                        = @{
        'Alpha2'      = 'QA'
        'CountryCode' = '634'
    }
    "Réunion"                                      = @{
        'Alpha2'      = 'RE'
        'CountryCode' = '638'
    }
    "Romania"                                      = @{
        'Alpha2'      = 'RO'
        'CountryCode' = '642'
    }
    "Russia"                                       = @{
        'Alpha2'      = 'RU'
        'CountryCode' = '643'
    }
    "Rwanda"                                       = @{
        'Alpha2'      = 'RW'
        'CountryCode' = '646'
    }
    "Saint Barthélemy"                             = @{
        'Alpha2'      = 'BL'
        'CountryCode' = '652'
    }
    "Saint Helena, Ascension and Tristan da Cunha" = @{
        'Alpha2'      = 'SH'
        'CountryCode' = '654'
    }
    "St. Kitts and Nevis"                          = @{
        'Alpha2'      = 'KN'
        'CountryCode' = '659'
    }
    "St. Lucia"                                    = @{
        'Alpha2'      = 'LC'
        'CountryCode' = '662'
    }
    "Saint Martin (French part)"                   = @{
        'Alpha2'      = 'MF'
        'CountryCode' = '663'
    }
    "St. Pierre and Miquelon"                      = @{
        'Alpha2'      = 'PM'
        'CountryCode' = '666'
    }
    "St. Vincent and the Grenadines"               = @{
        'Alpha2'      = 'VC'
        'CountryCode' = '670'
    }
    "Samoa"                                        = @{
        'Alpha2'      = 'WS'
        'CountryCode' = '882'
    }
    "San Marino"                                   = @{
        'Alpha2'      = 'SM'
        'CountryCode' = '674'
    }
    "São Tomé and Príncipe"                        = @{
        'Alpha2'      = 'ST'
        'CountryCode' = '678'
    }
    "Saudi Arabia"                                 = @{
        'Alpha2'      = 'SA'
        'CountryCode' = '682'
    }
    "Senegal"                                      = @{
        'Alpha2'      = 'SN'
        'CountryCode' = '686'
    }
    "Serbia"                                       = @{
        'Alpha2'      = 'RS'
        'CountryCode' = '688'
    }
    "Serbia and Montenegro (Former)"               = @{
        'Alpha2'      = 'CS'
        'CountryCode' = '891'
    }
    "Seychelles"                                   = @{
        'Alpha2'      = 'SC'
        'CountryCode' = '690'
    }
    "Sierra Leone"                                 = @{
        'Alpha2'      = 'SL'
        'CountryCode' = '694'
    }
    "Singapore"                                    = @{
        'Alpha2'      = 'SG'
        'CountryCode' = '702'
    }
    "Sint Maarten (Dutch part)"                    = @{
        'Alpha2'      = 'SX'
        'CountryCode' = '534'
    }
    "Slovakia"                                     = @{
        'Alpha2'      = 'SK'
        'CountryCode' = '703'
    }
    "Slovenia"                                     = @{
        'Alpha2'      = 'SI'
        'CountryCode' = '705'
    }
    "Solomon Islands"                              = @{
        'Alpha2'      = 'SB'
        'CountryCode' = '90'
    }
    "Somalia"                                      = @{
        'Alpha2'      = 'SO'
        'CountryCode' = '706'
    }
    "South Africa"                                 = @{
        'Alpha2'      = 'ZA'
        'CountryCode' = '710'
    }
    "South Georgia and the South Sandwich Islands" = @{
        'Alpha2'      = 'GS'
        'CountryCode' = '239'
    }
    "South Sudan"                                  = @{
        'Alpha2'      = 'SS'
        'CountryCode' = '728'
    }
    "Spain"                                        = @{
        'Alpha2'      = 'ES'
        'CountryCode' = '724'
    }
    "Sri Lanka"                                    = @{
        'Alpha2'      = 'LK'
        'CountryCode' = '144'
    }
    "Sudan"                                        = @{
        'Alpha2'      = 'SD'
        'CountryCode' = '729'
    }
    "Suriname"                                     = @{
        'Alpha2'      = 'SR'
        'CountryCode' = '740'
    }
    "Svalbard"                                     = @{
        'Alpha2'      = 'SJ'
        'CountryCode' = '744'
    }
    "Swaziland"                                    = @{
        'Alpha2'      = 'SZ'
        'CountryCode' = '748'
    }
    "Sweden"                                       = @{
        'Alpha2'      = 'SE'
        'CountryCode' = '752'
    }
    "Switzerland"                                  = @{
        'Alpha2'      = 'CH'
        'CountryCode' = '756'
    }
    "Syria"                                        = @{
        'Alpha2'      = 'SY'
        'CountryCode' = '760'
    }
    "Taiwan"                                       = @{
        'Alpha2'      = 'TW'
        'CountryCode' = '158'
    }
    "Tajikistan"                                   = @{
        'Alpha2'      = 'TJ'
        'CountryCode' = '762'
    }
    "Tanzania"                                     = @{
        'Alpha2'      = 'TZ'
        'CountryCode' = '834'
    }
    "Thailand"                                     = @{
        'Alpha2'      = 'TH'
        'CountryCode' = '764'
    }
    "Democratic Republic of Timor-Leste"           = @{
        'Alpha2'      = 'TL'
        'CountryCode' = '626'
    }
    "Togo"                                         = @{
        'Alpha2'      = 'TG'
        'CountryCode' = '768'
    }
    "Tokelau"                                      = @{
        'Alpha2'      = 'TK'
        'CountryCode' = '772'
    }
    "Tonga"                                        = @{
        'Alpha2'      = 'TO'
        'CountryCode' = '776'
    }
    "Trinidad and Tobago"                          = @{
        'Alpha2'      = 'TT'
        'CountryCode' = '780'
    }
    "Tunisia"                                      = @{
        'Alpha2'      = 'TN'
        'CountryCode' = '788'
    }
    "Turkey"                                       = @{
        'Alpha2'      = 'TR'
        'CountryCode' = '792'
    }
    "Turkmenistan"                                 = @{
        'Alpha2'      = 'TM'
        'CountryCode' = '795'
    }
    "Turks and Caicos Islands"                     = @{
        'Alpha2'      = 'TC'
        'CountryCode' = '796'
    }
    "Tuvalu"                                       = @{
        'Alpha2'      = 'TV'
        'CountryCode' = '798'
    }
    "Uganda"                                       = @{
        'Alpha2'      = 'UG'
        'CountryCode' = '800'
    }
    "Ukraine"                                      = @{
        'Alpha2'      = 'UA'
        'CountryCode' = '804'
    }
    "United Arab Emirates"                         = @{
        'Alpha2'      = 'AE'
        'CountryCode' = '784'
    }
    "United Kingdom"                               = @{
        'Alpha2'      = 'GB'
        'CountryCode' = '826'
    }
    "U.S. Minor Outlying Islands"                  = @{
        'Alpha2'      = 'UM'
        'CountryCode' = '581'
    }
    "United States"                                = @{
        'Alpha2'      = 'US'
        'CountryCode' = '840'
    }
    "Uruguay"                                      = @{
        'Alpha2'      = 'UY'
        'CountryCode' = '858'
    }
    "Uzbekistan"                                   = @{
        'Alpha2'      = 'UZ'
        'CountryCode' = '860'
    }
    "Vanuatu"                                      = @{
        'Alpha2'      = 'VU'
        'CountryCode' = '548'
    }
    "Bolivarian Republic of Venezuela"             = @{
        'Alpha2'      = 'VE'
        'CountryCode' = '862'
    }
    "Vietnam"                                      = @{
        'Alpha2'      = 'VN'
        'CountryCode' = '704'
    }
    "Virgin Islands, British"                      = @{
        'Alpha2'      = 'VG'
        'CountryCode' = '92'
    }
    "Virgin Islands"                               = @{
        'Alpha2'      = 'VI'
        'CountryCode' = '850'
    }
    "Wake Island"                                  = @{
        'Alpha2'      = 'XX'
        'CountryCode' = '581'
    }
    "Wallis and Futuna"                            = @{
        'Alpha2'      = 'WF'
        'CountryCode' = '876'
    }
    "Yemen"                                        = @{
        'Alpha2'      = 'YE'
        'CountryCode' = '887'
    }
    "Zambia"                                       = @{
        'Alpha2'      = 'ZM'
        'CountryCode' = '894'
    }
    "Zimbabwe"                                     = @{
        'Alpha2'      = 'ZW'
        'CountryCode' = '716'
    }
}

# Code to generate the above block:
# ---------------------------------
# $Countries_Body = New-Object -TypeName 'System.Text.StringBuilder'
# [void]$Countries_Body.AppendLine('$Countries = @{')
# Get-BiaAllActiveDirectoryNames | ForEach-Object {
#     $Country = Get-BiaCountryByActiveDirectoryName $_
#     [void]$Countries_Body.AppendLine(("`t`"{0}`" = {1}" -f $Country.ActiveDirectoryName,'@{'))
#     [void]$Countries_Body.AppendLine("`t`t'Alpha2' = '{0}'" -f $Country.Alpha2)
#     [void]$Countries_Body.AppendLine("`t`t'CountryCode' = '{0}'" -f $Country.Numeric)
#     [void]$Countries_Body.AppendLine("`t{0}" -f '}')
# }
# [void]$Countries_Body.AppendLine('}')
# $Countries_Body.ToString() | Set-Clipboard
# ---------------------------------

# Get any Alpha2 or CountryCodes that are assigned to more than one country.
$Countries_FullNames = $Countries.Keys
$Countries_Alpha2 = $Countries.GetEnumerator() | ForEach-Object { $_.Value.Alpha2 }
$Countries_CountryCodes = $Countries.GetEnumerator() | ForEach-Object { $_.Value.CountryCode }
$Countries_Ambiguous_Alpha2 = @(($Countries_Alpha2 | Group-Object | Where-Object { $_.Count -gt 1 }).Name)
$Countries_Ambiguous_CountryCodes = @(($Countries_CountryCodes | Group-Object | Where-Object { $_.Count -gt 1 }).Name)
