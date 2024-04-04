from flask import render_template, abort

#CustomErrorPages-1 - START
"""Fix"""
def handle_400(e):
    return render_template("custom_errors/400.html")
def handle_403(e):
    return render_template("custom_errors/403.html")
def handle_404(e):
    return render_template("custom_errors/404.html")
def handle_500(e):
    return render_template("custom_errors/50x.html")
def handle_505(e):
    return render_template("custom_errors/50x.html")
#CustomErrorPages-1 - END

#DebugModeON-2 - START
#DebugModeON-2 - END