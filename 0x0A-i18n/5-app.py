#!/usr/bin/env python3
"""Babel module"""
from flask import Flask, request, render_template, g
from flask_babel import Babel
app = Flask(__name__)
babel = Babel(app)


class Config():
    """Configuration class"""
    LANGUAGES = ["en", "fr"]


app.config.from_object(Config)
Babel.default_locale = 'en'
Babel.default_timezone = 'UTC'
users = {
    1: {"name": "Balou", "locale": "fr", "timezone": "Europe/Paris"},
    2: {"name": "Beyonce", "locale": "en", "timezone": "US/Central"},
    3: {"name": "Spock", "locale": "kg", "timezone": "Vulcan"},
    4: {"name": "Teletubby", "locale": None, "timezone": "Europe/London"},
}


@app.route('/')
def hello_world():
    """home route"""
    return render_template('5-index.html')


@babel.localeselector
def get_locale():
    """function that  determine the best
    match with our supported languages"""
    if request.args.get('locale'):
        return request.args.get('locale')
    else:
        return request.accept_languages.best_match(app.config['LANGUAGES'])


def get_user():
    """function that returns a user dictionary"""
    id = request.args.get('login_as')
    if id:
        return users[int(id)]
    else:
        return None


@app.before_request
def before_request():
    """find a user if any, and set
    it as a global on flask.g.user."""
    g.user = get_user()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
