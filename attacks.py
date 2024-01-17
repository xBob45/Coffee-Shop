attacks_config = {
    'SQLInjection': True,
    'SQLInjection2': True,
    'SensitiveInformationDisclosure': True,
    'ReflectedXSS': False,
    'StoredXSS': False,
    'InsufficientSessionInvalidation': False,
    'SensitiveDatawithinCookie': True,  #If 'True' set 'ForcedBrowsing' to 'None'
    'ForcedBrowsing': None,
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
    'CSRF': False, #If 'True' set 'CookiesWithoutSecurityAttributes' to 'None'
    'VulnerablePostgreSQL' : False,
    'SSRF' : False,
    'CompleteOmissionOfHashFunction' : None,
    'WeakHashFunction' : None, 
    'WeakHashFunctionWithSalt': True 
}

#TODO -> Adjust database queries according to gnerated hash function so the users could log in.