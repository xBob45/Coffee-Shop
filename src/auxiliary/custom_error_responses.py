from flask import render_template, abort

#CustomErrorPages-1 - START
#CustomErrorPages-1 - END

#DebugModeON-2 - START
"""Status: Vulnerable"""
#Description: CWE-489: Active Debug Code -> https://cwe.mitre.org/data/definitions/489.html
def handle_400(e):
    pass
def handle_403(e):
    pass
def handle_404(e):
    pass
def handle_413(e):
    pass
def handle_415(e):
    pass
def handle_500(e):
    pass
def handle_505(e):
    pass
#DebugModeON-2 - END