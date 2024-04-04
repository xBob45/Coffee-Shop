attacks_config = {
    'SQLInjection': False, #<-----
    'SQLInjection2': True,
    'SensitiveInformationDisclosure': True,
    'ReflectedXSS': False,
    'StoredXSS': False, #<-----
    'InsufficientSessionInvalidation': False,
    'ForcedBrowsing': None, #If you set this vulnerability to either "True" or "False" set "SensitiveDatawithinCookie" to "None"
    'HardCodedKey': True,
    'PathTraversal': True,
    'OSCommandInjection': False,
    'CookiesWithoutSecurityAttributes' : None, # Set to 'None' if you're going to set 'CSRF', 'SensitiveDatawithinCookie'
    'Clickjacking' : False,
    'InsufficientLogging':False,
    'InsertionOfSensitiveInformationIntoLogFile' : True,
    'WeakPasswordRequirements' : True,
    'IDOR': False,
    'CSRF': True, #If 'True' set 'CookiesWithoutSecurityAttributes' to 'None'
    'SensitiveDatawithinCookie': True,  #If you set this vulnerability to either "True" or "False" set "ForcedBrowsing" to "None"
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
