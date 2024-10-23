#!/usr/bin/env python3
""" App entry point
"""

from flask import Flask, render_template, request
from flask_babel import Babel

app = Flask(__name__)
babel = Babel(app)


class Config:
    """ Config class for Flask app
    """
    LANGUAGES = ["en", "fr"]
    BABEL_DEFAULT_LOCALE = "en"
    BABEL_DEFAULT_TIMEZONE = "UTC"


app.config.from_object(Config)



def get_locale() -> str:
    """
    This function is invoked for each request
    to select a language translation to use for that request
    """
    return request.accept_languages.best_match(app.config['LANGUAGES'])

babel.init_app(app, locale_selector=get_locale)

@app.route("/")
def index():
    """ index route
    """
    return render_template('2-index.html')


if __name__ == "__main__":
    app.run()
