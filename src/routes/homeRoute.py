from flask import Blueprint
from src.controllers.homeController import home, tips_and_tricks, guide_reader, coffee, tea, accessories, product_info

home_blueprint = Blueprint('home', __name__,)
home_blueprint.route('/')(home)
home_blueprint.route('/tips_and_tricks')(tips_and_tricks)
home_blueprint.route('/tips_and_tricks/guide')(guide_reader)
home_blueprint.route('/coffee')(coffee)
home_blueprint.route('/tea')(tea)
home_blueprint.route('/accessories')(accessories)
home_blueprint.route('/product')(product_info)


#SSRF-2 - START
#SSRF-2 - END