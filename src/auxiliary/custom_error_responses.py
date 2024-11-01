from flask import render_template, abort

#CustomErrorPages-1 - START
#CustomErrorPages-1 - END

#DebugModeON-2 - START
"""Status: Fixed"""
#Description: CWE-489: Active Debug Code -> https://cwe.mitre.org/data/definitions/489.html
def handle_400(e):
    return render_template("custom_errors/400.html")
def handle_403(e):
    return render_template("custom_errors/403.html")
def handle_404(e):
    return render_template("custom_errors/404.html")
def handle_413(e):
    return render_template("custom_errors/413.html")
def handle_415(e):
    return render_template("custom_errors/415.html")
def handle_500(e):
    return render_template("custom_errors/50x.html")
def handle_505(e):
    return render_template("custom_errors/50x.html")
#DebugModeON-2 - END