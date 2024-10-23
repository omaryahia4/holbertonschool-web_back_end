#!/usr/bin/env python3
"""Route API
"""
from typing import Dict
from flask import Flask, g, render_template, request
from flask_babel import Babel

app = Flask(__name__)
babel = Babel(app)
users = {
    1: {"name": "Balou", "locale": "fr", "timezone": "Europe/Paris"},
    2: {"name": "Beyonce", "locale": "en", "timezone": "US/Central"},
    3: {"name": "Spock", "locale": "kg", "timezone": "Vulcan"},
    4: {"name": "Teletubby", "locale": None, "timezone": "Europe/London"},
}


class Config:
    """Config class
    """
    LANGUAGES = ["en", "fr"]
    BABEL_DEFAULT_LOCALE = "en"
    BABEL_DEFAULT_TIMEZONE = "UTC"


app.config.from_object(Config)


def get_locale():
    """Returns a user dictionary or None based on the ID
    """
    lang = app.config['LANGUAGES']

    if 'locale' in request.args and request.args['locale'] in lang:
        return request.args['locale']
    return request.accept_languages.best_match(app.config['LANGUAGES'])


def get_user() -> Dict:
    """Finds a user if any, and set it as a global on flask.g.user
    """
    try:
        user_id = int(request.args.get('login_as'))
        if user_id in users.keys():
            return users[user_id]
    except Exception:
        return None


@app.before_request
def before_request():
    """Before request
    """
    user = get_user()
    if user:
        g.user = user


@app.route('/')
def index():
    """index.html
    """
    try:
        username = g.user['name']
    except Exception:
        username = None
    return render_template('5-index.html', username=username)


babel.init_app(app, locale_selector=get_locale)

if __name__ == '__main__':
    app.run()
