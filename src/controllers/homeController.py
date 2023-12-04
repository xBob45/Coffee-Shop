import functools
import os
from flask import (Blueprint, flash, g, redirect, render_template, request, session, url_for, send_file, abort)
import re

def home():
    return render_template("public/home.html")

def tips_and_tricks():
    return render_template("public/tips_and_tricks.html")

#PathTraversal-1 - START
#PathTraversal-1 - END


