attacks_config = {
    'SQLInjection': False,
    'SensitiveInformationDisclosure': True,
    'ReflectedXSS': True,
    'InsufficientSessionInvalidation': False,

    'SensitiveDatawithinCookie': False, 
    'SensitiveDatawithinCookie2': False, #This value has to be the same as the value of 'SensitiveDatawithinCookie'

    'ForcedBrowsing': False,
    'HardCodedKey': True,
    
    'DebugModeON': True,
    'PathTraversal': True,
    'OSCommandInjection': False,
}