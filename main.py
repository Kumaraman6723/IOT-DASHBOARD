from flask import Flask,jsonify
from flask_bootstrap import Bootstrap5
from flask_wtf.csrf import CSRFProtect
from authlib.integrations.flask_client import OAuth
from config import appConf
from routes import register_routes
from models import token_fn ,token_route
from functools import wraps

from collections import defaultdict


app = Flask(__name__)
app.config['SECRET_KEY'] = appConf.get("FLASK_SECRET")
Bootstrap5(app)
csrf = CSRFProtect(app)
oauth = OAuth(app)


oauth.register(
    "myApp",
    client_id=appConf.get("OAUTH2_CLIENT_ID"),
    client_secret=appConf.get("OAUTH2_CLIENT_SECRET"),
    server_metadata_url=appConf.get("OAUTH2_META_URL"),
    client_kwargs={
        "scope": "openid profile email https://www.googleapis.com/auth/user.birthday.read https://www.googleapis.com/auth/user.gender.read https://www.googleapis.com/auth/userinfo.profile"
    }
)

register_routes(app, oauth)


# Create routes dynamically
for token in token_fn():
    app.add_url_rule(f"/{token}",
                     endpoint=f"token_route_{token}",
                     view_func=csrf.exempt(token_route),
                     methods=["GET", 'POST'])


if __name__ == "__main__":
    app.run(debug=True, port=appConf.get("FLASK_PORT"))
