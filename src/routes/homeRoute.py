from flask import Blueprint
from controllers.homeController import home, tips_and_tricks, guide_reader

home_blueprint = Blueprint('home', __name__)
home_blueprint.route('/')(home)
home_blueprint.route('/tips_and_tricks')(tips_and_tricks)
home_blueprint.route('/tips_and_tricks/guide')(guide_reader)