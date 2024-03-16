attacks_config = {
    'SQLInjection': False, #<-----
    'SQLInjection2': True,
    'SensitiveInformationDisclosure': True,
    'ReflectedXSS': False,
    'StoredXSS': False, #<-----
    'InsufficientSessionInvalidation': False,
    'ForcedBrowsing': None,
    'HardCodedKey': True,
    'DebugModeON': True,
    'PathTraversal': False,
    'OSCommandInjection': False,
    'CookiesWithoutSecurityAttributes' : None,
    'Clickjacking' : True,
    'InsufficientLogging':False,
    'InsertionOfSensitiveInformationIntoLogFile' : True,
    'WeakPasswordRequirements' : True,
    'IDOR': False,
    'CSRF': True, #If 'True' set 'CookiesWithoutSecurityAttributes' to 'None'
    'SensitiveDatawithinCookie': True,  #If 'True' set 'ForcedBrowsing' to 'None'
    'VulnerablePostgreSQL' : False,
    'SSRF' : False,
    'CompleteOmissionOfHashFunction' : None, 
    'WeakHashFunction' : None, 
    'WeakHashFunctionWithSalt': False,
    'UnprotectedTransportofCredentials': False,
    'DirectoryListing':False,
    'CustomErrorPages': False,
    'BruteForce': True
}
