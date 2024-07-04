from dotenv import load_dotenv
load_dotenv('/var/www/html/app/.env')
import sys

sys.path.insert(0, "/var/www/html/app")

from app import app as application