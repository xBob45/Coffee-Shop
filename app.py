import os
from src import create_app
from dotenv import load_dotenv
load_dotenv()

host = str(os.getenv("HOST"))
port = int(os.getenv("PORT"))
debug = bool(os.getenv("DEBUG"))

app = create_app()
if __name__ == '__main__':  
    app.run(host=host, port=port, debug=debug)
