"""Start the authenticated gray-box VAPT API."""
from src.api import create_app
from src.config import settings

app = create_app("graybox")

if __name__ == "__main__":
    app.run(host=settings.api_host, port=settings.api_port, debug=False, threaded=True)
