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
import hmac
import time
import hashlib
import struct


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
app.secret_key = "S2aVUKbuu+H+BtJv6zU1fP2ewC7vhkR5"
login_manager = LoginManager()
login_manager.setup_app(app)
logging.basicConfig(level=logging.DEBUG)
user_store = {}

"""
This function will create OTP from a Pre-shared key, counter, name, service key
"""
def HOTP(S, N, C, digits=6, digestmod=hashlib.sha1):
    C_bytes = bytes(str(C) + str(S) + str(N), 'utf-8')
    hmac_digest = hmac.new(key=bytes(app.secret_key, 'utf-8'), msg=C_bytes,
                           digestmod=digestmod).hexdigest()
    return Truncate(hmac_digest)[-digits:]

"""
This function will called HOTP function with a specific clock (counter)
"""
def TOTP(S, N, digits=6, window=30, clock=None, digestmod=hashlib.sha1):
    if clock is None:
        clock = time.time()
    C = int(clock)
    return HOTP(S, N, C, digits=digits, digestmod=digestmod)

"""
The function will truncate the OTP
"""
def Truncate(hmac_digest):
    offset = int(hmac_digest[-1], 16)
    binary = int(hmac_digest[(offset * 2):((offset * 2) + 8)], 16) & 0x7fffffff
    return str(binary)

"""
this function will return the OTP
"""
def getToken(name, service_uid):
    C = getCounter(name, service_uid)
    if (C != None):
        return TOTP(service_uid, name, clock=C)

"""
this function will called TOTP function with counter of getCounter function called
"""
def checkOTPFromDB(name, service_uid, otp):
    C = getCounter(name, service_uid)
    if (C != None):
        if (TOTP(service_uid, name, clock=C) == otp):
            return True
        else:
            return False

"""
This function will return counter column from name and service uid 
"""
def getCounter(name, service_uid):
    conn = None
    try:
        params = config()
        conn = psycopg2.connect(**params)
        cur = conn.cursor()
        cur.execute("SELECT counter FROM users WHERE name='{}' AND service_uid='{}'".format(name, service_uid))
        print("Check OTP: ", cur.rowcount)
        row = cur.fetchone()
        
        print(row)
        if (cur.rowcount >= 1):
            return row[0]
        else:
            return None
 
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        return False
    finally:
        if conn is not None:
            conn.close()

"""
This function is called when checkOTP, activated or login route is called
This function will check if the OTP is expired.
If the OTP is expired, the function will update counter column
"""
def updateToken(name, service_uid):
    C_db = getCounter(name, service_uid)
    print("{} {}".format(str(C_db + 100), int(time.time())))
    if (C_db + 100 <= int(time.time())):
        conn = None
        try:
            params = config()
            conn = psycopg2.connect(**params)
            cur = conn.cursor()
            clock = time.time()
            C = int(clock)
            cur.execute("UPDATE users set counter={} WHERE name='{}' AND service_uid='{}'".format(C, name, service_uid))
            print("Update token: ", cur.rowcount)
            conn.commit()
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

"""
This function will update user in db to fill activation column
"""
def activateUserDB(name, service_uid):
    conn = None
    try:
        params = config()
        conn = psycopg2.connect(**params)
        cur = conn.cursor()
        cur.execute("UPDATE users set activation=true WHERE name='{}' AND service_uid='{}'".format(name, service_uid))
        print("Activate user: ", cur.rowcount)
        conn.commit()
        print(row)
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

"""
This function will check if user with specific name or oid is in db
"""
def checkUser(name, oid):
    conn = None
    try:
        params = config()
        conn = psycopg2.connect(**params)
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE name='{}' OR oid='{}'".format(name, oid))
        print("Check Users: ", cur.rowcount)
        if (cur.rowcount >= 1):
            return False
        else:
            return True
 
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        return False
    finally:
        if conn is not None:
            conn.close()

"""
This function will create a user in db and call TOTP function (a function to create TOTP)
"""
def createUser(name, oid, service_uid):
    conn = None
    try:
        params = config()
        conn = psycopg2.connect(**params)
        cur = conn.cursor()
        if (checkUser(name, oid)):
            clock = time.time()
            C = int(clock)
            cur.execute("INSERT INTO users(name, oid, counter, service_uid) values('{}','{}',{},'{}')".format(name, oid, C, service_uid))
            conn.commit()
            print("Create user: ", cur.rowcount)
            return TOTP(service_uid, name)
 
            cur.close()
        else:
            return None
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        return None
    finally:
        if conn is not None:
            conn.close()

"""
register route
This route will be called by client
This function will store, in db, Name, OID, Counter, and Service UID. And return the OTP created
"""
@app.route("/register", methods=['POST'])
def register():
    if not request.json or not 'name' in request.json or not 'service_uid' in request.json or not 'user_pub' in request.json:
        return jsoninfy({'error': 'name, service_uid and user_pub are required'}), 401
    
    otp = createUser(request.json['name'], request.json['user_pub'], request.json['service_uid'])
    print(otp)

    if (otp == None):
        return jsonify({'error': 'name or oid false'}), 401
    else:
        return jsonify({'otp': otp}), 201

"""
check OTP route
This route will be called by register function of service provider
This function will check if OTP is valid or not and return it
"""
@app.route("/checkOTP", methods=['GET'])
def checkOTP():
    if not request.args or request.args.get('otp') == None or request.args.get('name') == None or request.args.get('service_uid') == None:
        return jsonify({'error': 'name, otp and service_uid are required'}), 401
    
    if (checkOTPFromDB(request.args.get('name'), request.args.get('service_uid'), request.args.get('otp'))):
        updateToken(request.args.get('name'), request.args.get('service_uid'))
        token = getToken(request.args.get('name'), request.args.get('service_uid'))
        return jsonify({'success': 'OTP is valid', 'otp': token}), 201
    else:
        return jsonify({'error': 'name, otp or service_uid is not valid'}), 401

"""
activate user route
This route will be called by client to activate his account
"""
@app.route("/activated", methods=['GET'])
def activateUser():
    if not request.args or request.args.get('otp') == None or request.args.get('name') == None or request.args.get('service_uid') == None:
        return jsonify({'error': 'name, otp and service_uid are required'}), 401
    
    if (checkOTPFromDB(request.args.get('name'), request.args.get('service_uid'), request.args.get('otp'))):
        activateUserDB(request.args.get('name'), request.args.get('service_uid'))
        updateToken(request.args.get('name'), request.args.get('service_uid'))
        token = getToken(request.args.get('name'), request.args.get('service_uid'))
        return jsonify({'success': 'User activated', 'otp': token}), 201
    else:
        return jsonify({'error': 'name, otp or service_uid is not valid'}), 401

"""
login route
This route will be called by login function of service provider
This route will check if the otp is correct and return it
"""
@app.route("/login", methods=['POST'])
def login():
    if not request.json or not 'name' in request.json or not 'service_uid' in request.json or not 'otp' in request.json:
        return jsonify({'error': 'name, otp and service_uid are required'}), 401
    
    if (checkOTPFromDB(request.json['name'], request.json['service_uid'], request.json['otp'])):
        updateToken(request.json['name'], request.json['service_uid'])
        token = getToken(request.json['name'], request.json['service_uid'])
        return jsonify({'success': 'login successful', 'otp': token}), 201
    else:
        return jsonify({'error': 'name, otp or service_uid is not valid'}), 401

@app.route("/")
def main_page():
    return "Hello"


if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5001))
    if port == 5001:
        app.debug = True
    app.run(host='0.0.0.0', port=port)