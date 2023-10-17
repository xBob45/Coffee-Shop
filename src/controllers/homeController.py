import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)

def home():
    return render_template("public/home.html")