import os
from dotenv import load_dotenv

load_dotenv()
SITE_KEY = os.getenv("CAPTCHA_SITE_KEY")
SECRET_KEY = os.getenv("CAPTCHA_SECRET_KEY")

print(SITE_KEY)