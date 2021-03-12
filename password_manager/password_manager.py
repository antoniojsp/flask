#H.E librariess
from phe import paillier
#flask libraries
import json
from flask import request, url_for
from flask_api import FlaskAPI, status, exceptions
from flask import send_from_directory
from flask_cors import CORS
import requests
import logging
import os

#RSA
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii
#sign
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64

import hashlib

#mongodb
#register new voters
import pymongo # modules
from pymongo import MongoClient

app = FlaskAPI(__name__)
cors = CORS(app, resources={r'/*': {"origins": '*'}})

#mongodb
client = MongoClient("mongodb+srv://antonio:antonio@cluster0.hb8y0.mongodb.net/experiment?retryWrites=true&w=majority", ssl=True,ssl_cert_reqs='CERT_NONE')
# db = client.register  # create database
# collection = db.voter # collection of voters

db1 = client.private  # create database
password_manager = db1.private_key # for voters priv key

'''
Database for private keys
When the user register to vote, to public key goes to the electos database and the private key goes to the password manager database. These private key is encrypted using a hash generated from the password.
'''

@app.route("/salt", methods=['GET','POST'])
def salt():
    if request.method == 'POST':
        id = json.loads(request.data)

        
        if password_manager.count_documents({ "id": id[0] }, limit = 1) != 0: # checks if the voter has been already register.
            for i in password_manager.find({'id':id[0]}):# look up for the public key in the Authority database
                temp = i
            results = temp['salt']
        else:
            results = 1

        return json.dumps(results)


@app.route("/download", methods=['GET','POST'])
def download():
    if request.method == 'POST':
        id = json.loads(request.data)
        app.logger.info(id)
        for i in password_manager.find({'id':id[0]}):# look up for the public key in the Authority database
            temp = i
        app.logger.info("aca")

        if temp['hash'] != id[1]:
            return json.dumps(1)
        app.logger.info("bien")


        return json.dumps(temp['priv_key'])





if __name__ == "__main__":
    app.run(host='0.0.0.0', port=6000, debug=True)
