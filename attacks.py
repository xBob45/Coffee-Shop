attacks_config = {
    'SQLInjection': False, #<-----
    'SQLInjection2': True,
    'SensitiveInformationDisclosure': True,
    'ReflectedXSS': False,
    'StoredXSS': True, #<-----
    'InsufficientSessionInvalidation': False,
    'ForcedBrowsing': None, #If you set this vulnerability to either "True" or "False" set "SensitiveDatawithinCookie" to "None"
    'HardCodedKey': True,
    'PathTraversal': False,
    'OSCommandInjection': False,
    'CookiesWithoutSecurityAttributes' : None, # Set to 'None' if you're going to set 'CSRF', 'SensitiveDatawithinCookie'
    'Clickjacking' : False,
    'InsufficientLogging':True,
    'InsertionOfSensitiveInformationIntoLogFile' : True,
    'WeakPasswordRequirements' : True,
    'IDOR': True,
    'CSRF': True, #If 'True' set 'CookiesWithoutSecurityAttributes' to 'None'
    'SensitiveDatawithinCookie': True,  #If you set this vulnerability to either "True" or "False" set "ForcedBrowsing" to "None"
    'VulnerablePostgreSQL' : False,
    'SSRF' : False,
    'CompleteOmissionOfHashFunction' : None, 
    'WeakHashFunction' : None, 
    'WeakHashFunctionWithSalt': False,
    'UnprotectedTransportofCredentials': False,
    'DirectoryListing': True,
    'CustomErrorPages': None, #If you set this vunerability to either "True" or "False" set 'DebugModeON' to 'None'
    'DebugModeON': False, #If you set this vunerability to either "True" or 'False' set 'CustomErrorPages' to 'None'. Also, in order to exploit this set 'UnprotectedTransportofCredentials' to 'False'
    'BruteForce': False,
    'MaliciousFileUpload':True, #For exploitation, set 'DirectoryListing' to 'True'
    'HardCodedCredentials':False,
    'FunctionalityFromUntrustedSource':True
}
