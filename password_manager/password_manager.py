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

db1 = client.private  # access/create database
password_manager = db1.private_key # for voters priv key

'''
Database for private keys
When the user register to vote, to public key goes to the electos database and the private key goes to the password manager database. These private key is encrypted using a hash generated from the password.
'''

'''
return salts when the client ask. that salt is used to hash the master password
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

'''
After the salt is obtain, the master password is hashed using this salt and the hash is sent to download() in the password_manager for aunthetication. This hash (with 5000 rounnds) will be hashed one more round and compare with the hash stored inn the database for the id provided. Everythinng checks out, it sent the encrypted private key back to the cliene, otherwise, it returns 1 as a value to indicate error.
'''
@app.route("/download", methods=['GET','POST'])
def download():
    if request.method == 'POST':
        id = json.loads(request.data)

        for i in password_manager.find({'id':id[0]}):# look up for the public key in the Authority database
            temp = i

        #if fails, returns 1
        if temp['hash'] != id[1]:# id[1] can be only obtain by hashing the right master passwoord.
            return json.dumps(1) #returns 1 if fails

        return json.dumps(temp['priv_key'])# otherwise, sends encrypted private key

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=6000, debug=True)
