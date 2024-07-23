import bleach
from functools import wraps
from flask_login import current_user
import src.log_config as log_config
from werkzeug.exceptions import Forbidden, BadRequest
from flask import Blueprint, redirect, url_for, session, abort, request


def check_if_admin(func):
    #SensitiveDatawithinCookie-3 - START
    """Status: Fixed"""
    #Description: CWE-315: Cleartext Storage of Sensitive Information in a Cookie -> https://cwe.mitre.org/data/definitions/315.html
    @wraps(func)
    def decorated_view(*args, **kwargs):
        try:
            #Only authenticated users with role 'admin' can access admin panel
            if current_user.is_authenticated:
                if current_user.roles.name == 'admin':
                    log_config.logger.info("User %s accessed the admin panel." % bleach.clean(current_user.username), extra={'ip_address': request.remote_addr})
                    return func(*args, **kwargs) #If everything is OK, let user proceed.
                else:
                    log_config.logger.error("User tried to access the admin panel and failed as a result of insufficient privileges.", extra={'ip_address': request.remote_addr})
                    raise Forbidden()
            return redirect(url_for('auth.login'))
        except Forbidden:
            abort(403)
        except Exception as e:
            log_config.logger.error("Error occurred while accessing admin panel. Exception: %s" % e, extra={'ip_address': request.remote_addr})
            abort(400)
    #SensitiveDatawithinCookie-3 - END

    #ForcedBrowsing-1 - START
    #ForcedBrowsing-1 - END
    return decorated_view