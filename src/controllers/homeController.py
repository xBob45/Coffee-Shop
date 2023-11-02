import functools
import os
from flask import (Blueprint, flash, g, redirect, render_template, request, session, url_for, send_file, abort)
import re
from attacks import config




PathTraversal = config.getboolean('attacks', 'PathTraversal')

def home():
    return render_template("public/home.html")


def tips_and_tricks():
    return render_template("public/tips_and_tricks.html")


if PathTraversal == True:
    #---------------------------------------------A05 - Path Traversal - START----------------------------------------------
    def guide_reader():
        #../../../../../../etc/passwd

        #Extracts file from 'file_name' parameter
        file_name = request.args.get('file_name')

        #Creates a path by concatenating '/home/vojta/Bakalarka/Coffee-Shop/src/' and 'guides'
        guides_dir = os.path.join(os.getcwd(), 'guides')

        #Creates path to the requested file by concatenating '/home/vojta/Bakalarka/Coffee-Shop/src/guides' and '<file_name>'
        requested_file = os.path.join(guides_dir, file_name)
        
        #Opens the file located at the location of 'requested_file' for reading ('r')
        file = open(requested_file, 'r')
        content = file.read()
        return render_template("public/guide.html", content=content)
        #---------------------------------------------A05 - Path Traversal - End---------------------------------------------
else:
    def check_path(basedir, path, follow_symlinks=True):
        """Function checks for safety of a given path."""
        # basedir - base dir against which 'path' is compared -> /home/vojta/Bakalarka/Coffee-Shop/src/guides
        # path - path that subject of control -> /home/vojta/Bakalarka/Coffee-Shop/src/guides/guide1.txt[OK] or /etc/passwd[NOT OK]
        # follow_symlinks - if 'True' function will also resolve symbolic links and checks if it safe.
        if follow_symlinks:
            #Resolves the symbolic links if any
            matchpath = os.path.realpath(path)
            #print(matchpath)
        else:
            matchpath = os.path.abspath(path)
            #print(matchpath)
            
        #Return 'True' or 'False' based on if base directory is the common directory between 'basedir' and 'matchpath'
        #print(basedir)
        print(basedir == os.path.commonpath((basedir, matchpath)))
        return basedir == os.path.commonpath((basedir, matchpath))

    def guide_reader():
        file_name = request.args.get('file_name')
        #FIRST MEASURE OF PROTECTION -> ALLOWED PATTERN
        allowed_pattern = r'^[guide0-9.txt]+$'
        if re.match(allowed_pattern, file_name):
            guides_dir = os.path.join(os.getcwd(), 'guides')
            requested_file = os.path.join(guides_dir, file_name)

            #SECOND MEASURE OF PROTECTION -> PATH VALIDATION
            if check_path(guides_dir, requested_file):
                try:
                    with open(requested_file, 'r') as file:
                        content = file.read()
                    return render_template("public/guide.html", content=content)
                except FileNotFoundError:
                    abort(404)
            else:
                abort(404)
        else:
            #print("Unallowed pattern")
            abort(404)

