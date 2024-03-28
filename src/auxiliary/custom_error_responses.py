from flask import render_template, abort

#CustomErrorPages-1 - START
#CustomErrorPages-1 - END

#DebugModeON-2 - START
"""Vulnerability"""
def handle_400(e):
    abort(400)
def handle_403(e):
    abort(403)
def handle_404(e):
    abort(404)
def handle_500(e):
    abort(500)
def handle_505(e):
    abort(505)
#DebugModeON-2 - END