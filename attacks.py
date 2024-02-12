attacks_config = {
    'SQLInjection': False, #<-----
    'SQLInjection2': True,
    'SensitiveInformationDisclosure': True,
    'ReflectedXSS': False,
    'StoredXSS': True, #<-----
    'InsufficientSessionInvalidation': False,
    'SensitiveDatawithinCookie': None,  #If 'True' set 'ForcedBrowsing' to 'None'
    'ForcedBrowsing': False,
    'HardCodedKey': True,
    'DebugModeON': True,
    'PathTraversal': True,
    'OSCommandInjection': True,
    'CookiesWithoutSecurityAttributes' : None,
    'Clickjacking' : True,
    'InsufficientLogging':True,
    'InsertionOfSensitiveInformationIntoLogFile' : True,
    'WeakPasswordRequirements' : True,
    'IDOR': False,
    'CSRF': True, #If 'True' set 'CookiesWithoutSecurityAttributes' to 'None'
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
