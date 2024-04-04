attacks_config = {
    'SQLInjection': False, #<-----
    'SQLInjection2': True,
    'SensitiveInformationDisclosure': True,
    'ReflectedXSS': False,
    'StoredXSS': False, #<-----
    'InsufficientSessionInvalidation': False,
    'ForcedBrowsing': None,
    'HardCodedKey': True,
    'PathTraversal': True,
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
    'DirectoryListing': False,
    'CustomErrorPages': False, #If you set this vunerability to either "True" or "False" set 'DebugModeON' to 'None'
    'DebugModeON': None, #If you set this vunerability to either "True" or 'False' set 'CustomErrorPages' to 'None'. Also, in order to exploit this set 'UnprotectedTransportofCredentials' to 'False'
    'BruteForce': True,
    'MaliciousFileUpload':False, #For exploitation, set 'DirectoryListing' to 'True'
    'HardCodedCredentials':False,
    'FunctionalityFromUntrustedSource':True
}
