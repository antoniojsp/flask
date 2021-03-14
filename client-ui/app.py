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

# for key encryption
from werkzeug.security import generate_password_hash, check_password_hash
import crypt  # generates salt




#flask instance
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




'''
Voter registration:

This emulate how a voter would request to be registered.
Once their information is verify for the correspondent authority (out of the scope of this project) The register_voter() would get the info that the user input in the website, like its name, last name, DOB, id and secret password.

This service would take that data and first, generate a pair of RSA keys, one (public key) will be stored along with the person id and a  boolean indicating if the person has voted or not in the database that manage the electors database ("register" database, "voter" collection in Atlas Mongodb). Then, the private key would encrypted using the hashed password (sha256, 5000 rounds) and stored in the database for private keys (acts like a "password manager") along with the random salt, person id and a hash from the master password that has been hashed 5000 + 1 times.
'''


'''
Generate both private and public key for RSA signing
'''
def generate_keys():
    keyPair = RSA.generate(3072)
    pubKey = keyPair.publickey()
    pubKeyPEM = pubKey.exportKey()
    a = pubKeyPEM.decode('ascii')
    privKeyPEM = keyPair.exportKey()
    b = privKeyPEM.decode('ascii')

    return RSA.import_key(a), RSA.import_key(b)

def generate_hashes(password, salt):
    #insert to private key (password manager) database
    password_string= str.encode(password)  
    a = hashlib.pbkdf2_hmac('sha256', password_string, salt.encode(), 5000) # for encrypt
    # b = hashlib.pbkdf2_hmac('sha256', str.encode(a.hex()), salt.encode(), 1) # for aunthenticate
    b = hashlib.pbkdf2_hmac('sha256', password_string, salt.encode(), 5001) # for aunthenticate


    return a, b

@app.route("/register", methods=["POST","GET"])
def register_voter():
    if request.method == "POST":
        if request.form.get:
            #gets all the data from the website
            fname = request.form.get("fname")
            lname = request.form.get("lname")
            date = request.form.get("bday")
            id_num =  request.form.get("id") 
            password =  request.form.get("Password") 
            #generate keys to be stored
            pub, priv = generate_keys()

            if collection.count_documents({ "id": id_num }, limit = 1) == 0: # checks if the voter has been already register.

                # insert to electors database
                #TO DO: use this hash value to verify if the vote has been counted
                hash_code = fname+lname+date
                hash_result = hashlib.sha256(hash_code.encode()) # generate a hash number from the name and id number.

                
                salt = crypt.mksalt(crypt.METHOD_SHA512) # salt to add the authen hash
                hash_encrypt, hash_authenticate = generate_hashes(password, salt) # get hashes to aunthentica and decrypt
                priv_encoded = cryptocode.encrypt(priv.exportKey().decode('ascii'), hash_encrypt.hex()) # encrypt private key

                # adding to electors's database the id number, the hash for check if voted was countes, boolean if the person votes, public key (plain text, to verify signature from the cl
                collection.insert_one({ "id":id_num, "hash":hash_result.hexdigest(), "has_votes":False, "pk": pub.exportKey().decode('ascii')})
                # adding to password manager the id number, the hash aunthentication, salt and the encrypted private key
                password_manager.insert_one({"id":id_num, "hash":hash_authenticate.hex(), "salt":salt, "priv_key":priv_encoded})
                flash("The voter with id #"+id_num+" has been registered. Hash value: "+ hash_result.hexdigest())

            else:
                # in case the voter is already registered.
                flash(id_num + " is already registered")
                app.logger.info("Voter already registered.")
                return render_template("register_voters.html")


    return render_template("register_voters.html")


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=7000, debug=True)
