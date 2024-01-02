import functools
import os
from flask import (Blueprint, flash, g, redirect, render_template, request, session, url_for, send_file, abort)
import re
from urllib.request import urlopen
from urllib.error import URLError
from urllib.parse import urlparse

def home():
    return render_template("public/home.html")

def tips_and_tricks():
    return render_template("public/tips_and_tricks.html")

#PathTraversal-1 - START
def guide_reader():
    """Vulnerability"""
    #../../../../../../etc/passwd
    #Extracts file from 'file_name' parameter
    file_name = request.args.get('file_name')

    #Creates a path by concatenating '/home/vojta/Bakalarka/Coffee-Shop/src/' and 'guides'
    guides_dir = os.path.join(os.getcwd(), 'guides')

    #Creates path to the requested file by concatenating '/home/vojta/Bakalarka/Coffee-Shop/src/guides' and '<file_name>'
    requested_file = os.path.join(guides_dir, file_name)
        
    #Opens the file located at the location of 'requested_file' for reading ('r')
    with open(requested_file, 'r') as file:
        content = file.read()
    
    return render_template("public/guide.html", content=content)
#PathTraversal-1 - END


#SSRF-1 - START
#SSRF-1 - END

    
