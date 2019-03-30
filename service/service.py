#!/usr/bin/env python
# -*- coding: utf-8 -*-
import base64
import logging
import os
import urllib
import uuid
import zlib

from flask import Flask
from flask import redirect
from flask import request
from flask import url_for
from flask import abort
from flask import jsonify
from flask_login import LoginManager
from flask_login import UserMixin
from flask_login import current_user
from flask_login import login_required
from flask_login import login_user
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import entity
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
import psycopg2
from config import config
import requests
import json


# PER APPLICATION configuration settings.
# Each SAML service that you support will have different values here.
idp_settings = {
    u'example.okta.com': {
        u"metadata": {
            "local": [u'./example.okta.com.metadata']
        }
    },
}
app = Flask(__name__)
app.secret_key = "c372aff2-6564-4aa6-95e8-c4d607544c12"
login_manager = LoginManager()
login_manager.setup_app(app)
logging.basicConfig(level=logging.DEBUG)
user_store = {}


"""
this function will create user in db with name and password
"""
def createUser(name, password):
    conn = None
    try:
        params = config()
        conn = psycopg2.connect(**params)
        cur = conn.cursor()
        cur.execute("INSERT INTO users(name, password) VALUES('{}','{}')".format(name, password))
        conn.commit()
        cur.close()
        return True
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        return False
    finally:
        if conn is not None:
            conn.close()

"""
this function is called by login function to check if name and password are in db
"""
def checkUserAndPassword(name, password):
    conn = None
    try:
        params = config()
        conn = psycopg2.connect(**params)
        cur = conn.cursor()
        cur.execute("SELECT name FROM users WHERE name='{}' AND password='{}'".format(name, password))
        print("The number of parts: ", cur.rowcount)
        if (cur.rowcount >= 1):
            return True
        else:
            return False
 
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        return False
    finally:
        if conn is not None:
            conn.close()


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

"""
register route
This route will be called by user to register
This function will called the checkOTP route of OTP provider to check if the OTP is correct
And the function will create a new user in db with name and password
"""
@app.route("/register", methods=['POST'])
def register():
    if not request.json or not 'name' in request.json or not 'password' in request.json or not 'otp_id' in request.json:
        abort(400)

    
    #call OTP provider with name and otp_id
    r = requests.get("http://127.0.0.1:5001/checkOTP", {"name": request.json['name'],"service_uid": app.secret_key,"otp": request.json['otp_id']})
    if (r.status_code == 201):
        createUser(request.json['name'], request.json['password'])
        return jsonify({'success': 'registration is OK', 'otp': r.json()['otp']}), 201
    else:
        return jsonify({'error': 'registration is not ok'}), 401

"""
login route
This route will be called by client to login
This function will check is name and password are correct and call login route of OTP Provider to check if OTP is correct
"""
@app.route("/login", methods=['POST'])
def login():
    if not request.json or not 'name' in request.json or not 'password' in request.json or not 'otp_id' in request.json:
        abort(400)
    
    if (checkUserAndPassword(request.json['name'], request.json['password'])):
        headers = {
            'Content-Type': 'application/json',
        }
        data = {
            "name": request.json['name'],
            "service_uid": app.secret_key,
            "otp": request.json['otp_id']
        }
        r = requests.post("http://127.0.0.1:5001/login", headers=headers, data=json.dumps(data))
        if (r.status_code == 201):
            return jsonify({'success': 'login successful', 'otp': r.json()['otp']}), 201
        else:
            return jsonify({'error': 'name or password or otp false'}), 401
    else:
        return jsonify({'error': 'name or password or otp false'}), 401

@app.route("/")
def main_page():
    return "Hello"

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    if port == 5000:
        app.debug = True
    app.run(host='0.0.0.0', port=port)