attacks_config = {
    'SQLInjection': False,
    'SQLInjection2': True,
    'SensitiveInformationDisclosure': True,
    'ReflectedXSS': True,
    'StoredXSS': False,
    'InsufficientSessionInvalidation': False,
    'SensitiveDatawithinCookie': False,  #If 'True' set 'ForcedBrowsing' to 'None'
    'ForcedBrowsing': None,
    'HardCodedKey': True,
    'DebugModeON': True,
    'PathTraversal': True,
    'OSCommandInjection': True,
    'CookiesWithoutSecurityAttributes' : None,
    'Clickjacking' : True,
    'InsufficientLogging':True,
    'InsertionOfSensitiveInformationIntoLogFile' : True,
    'WeakPasswordRequirements' : False,
    'IDOR': False,
    'CSRF': False, #If 'True' set 'CookiesWithoutSecurityAttributes' to 'None'
    'VulnerablePostgreSQL' : False,
    'SSRF' : False,
}