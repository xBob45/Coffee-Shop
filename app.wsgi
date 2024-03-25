#!/usr/bin/python3
import sys
import os
sys.path.insert(0, '/var/www/html/Coffee-Shop/')
from src import create_app
application = create_app()