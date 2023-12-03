attacks_config = {
    'SQLInjection': False,
    'SensitiveInformationDisclosure': True,
    'ReflectedXSS': True,
    'InsufficientSessionInvalidation': False,
    'SensitiveDatawithinCookie': True,  #If 'True' set 'ForcedBrowsing' to 'None'
    'ForcedBrowsing': None,
    'HardCodedKey': True,
    'DebugModeON': True,
    'PathTraversal': True,
    'OSCommandInjection': True,
    'CookiesWithoutSecurityAttributes' : True,
    'Clickjacking' : True,
    'InsufficientLogging':True,
    'InsertionOfSensitiveInformationIntoLogFile' : True,
    'InsufficientLogging' : True
}