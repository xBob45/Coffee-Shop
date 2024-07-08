import bleach
from functools import wraps
from flask_login import current_user
import src.log_config as log_config
from werkzeug.exceptions import Forbidden, BadRequest
from flask import Blueprint, redirect, url_for, session, abort, request


def check_if_admin(func):
    #SensitiveDatawithinCookie-3 - START
    #SensitiveDatawithinCookie-3 - END

    #ForcedBrowsing-1 - START
    #ForcedBrowsing-1 - END
    return decorated_view