from flask import Flask, render_template, json, request, flash, redirect, url_for
import requests
import os
#register new voters
import pymongo # modules
from pymongo import MongoClient
#RSA
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii
#sign
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import hashlib
import cryptocode

#create keys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

#flask
app = Flask(__name__)

#message flash
app.secret_key = "temporal location"

#hash
import hashlib

#mongodb
client = MongoClient("mongodb+srv://antonio:antonio@cluster0.hb8y0.mongodb.net/experiment?retryWrites=true&w=majority", ssl=True,ssl_cert_reqs='CERT_NONE')
db = client.register  # create database
collection = db.voter # collection of voters

db1 = client.private  # create database
password_manager = db1.private_key # for voters priv key

# index. Where the vote is casted.
@app.route('/', methods=['POST','GET'])
def index():

    return render_template('home.html')

# return results from server_decrypt
@app.route('/results', methods=['POST','GET'])
def results():
    resultados = requests.post('http://server_decrypt:90/results').json() #request the results of the tally from the server. The server handles the counting of the data encrypted    
    return render_template('results.html', lista=resultados['output'])

# reset too zero
@app.route("/new", methods=["POST","GET"])
def new():
    #delete the tally from mongodb and fill up a new one with all the stats in zero (encrypted)
    requests.post('http://server_decrypt:90/new').text
    return render_template("home.html")

@app.route("/panel", methods=["POST","GET"])
def panel():
    #delete the tally from mongodb and fill up a new one with all the stats in zero (encrypted)
    return render_template("control_panel.html")


from werkzeug.security import generate_password_hash, check_password_hash
# register voter (acts like the voter register center, needs name bday id and provides a hash number plus creates a public and private key)
@app.route("/register", methods=["POST","GET"])
def register_voter():
    if request.method == "POST":
        if request.form.get:
            fname = request.form.get("fname")
            lname = request.form.get("lname")
            date = request.form.get("bday")
            id_num =  request.form.get("id") 
            password =  request.form.get("Password") 

            keyPair = RSA.generate(3072)
            # keys. In normal situation, these keys would be generated for the system and use for register a new voter. For testing, we are using hardcode keys in private.pem and receiver.pm 
            pubKey = keyPair.publickey()
            pubKeyPEM = pubKey.exportKey()
            a = pubKeyPEM.decode('ascii')
            privKeyPEM = keyPair.exportKey()
            b = privKeyPEM.decode('ascii')
            pub = RSA.import_key(a)
            priv = RSA.import_key(b)
            # generate salt
            # generate hash aunthentication with the password and salt with 5001 rounds
            # encrypt private key using the hash oof the password with 5000 rounds 
            # add id, hash auntheticate, salt, privatekey encrypted to the password_manager database

            hash_code = fname+lname+date
            hash_result = hashlib.sha256(hash_code.encode()) # generate a hash number from the name and id number.
            
            if collection.count_documents({ "id": id_num }, limit = 1) == 0: # checks if the voter has been already register.

                # insert to electors database
                collection.insert_one({ "id":id_num, "hash":hash_result.hexdigest(), "has_votes":False, "pk": pub.exportKey().decode('ascii')})
                
                #insert to private key (password manager) database
                salt = "hola"
                password_string= str.encode(password)  
                password_hash = hashlib.pbkdf2_hmac('sha256', password_string, salt.encode(), 5001)
                password_key = hashlib.pbkdf2_hmac('sha256', password_string, salt.encode(), 5000)

                # #encrypt and send for storage
                priv_encoded = cryptocode.encrypt(priv.exportKey().decode('ascii'), password_key.hex())
               
                password_manager.insert_one({"id":id_num, "hash":password_hash.hex(), "salt":salt, "priv_key":priv_encoded})
                flash("The voter with id #"+id_num+" has been registered. Hash value: "+ hash_result.hexdigest())

            else:
                flash(id_num + " is already registered")
                app.logger.info("Voter already registered.")
                return render_template("register_voters.html")


    return render_template("register_voters.html")


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=7000, debug=True)
