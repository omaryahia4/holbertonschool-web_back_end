#!/usr/bin/env python3
"""Babel module"""
from flask import Flask, request, render_template
from flask_babel import Babel

app = Flask(__name__)
babel = Babel(app)


class Config():
    """Configuration class"""
    LANGUAGES = ["en", "fr"]


app.config.from_object(Config)
Babel.default_locale = 'en'
Babel.default_timezone = 'UTC'


@app.route('/')
def hello_world():
    """home route"""
    return render_template('4-index.html')


@babel.localeselector
def get_locale():
    """function that  determine the best
    match with our supported languages"""
    if request.args.get('locale'):
        return request.args.get('locale')
    else:
        return request.accept_languages.best_match(app.config['LANGUAGES'])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
