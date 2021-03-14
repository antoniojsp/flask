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
import cryptocode

#register new voters
import pymongo # modules
from pymongo import MongoClient


app = FlaskAPI(__name__)
cors = CORS(app, resources={r'/*': {"origins": '*'}})

client = MongoClient("mongodb+srv://antonio:antonio@cluster0.hb8y0.mongodb.net/experiment?retryWrites=true&w=majority", ssl=True,ssl_cert_reqs='CERT_NONE')
db = client.register  # create database
collection = db.voter # collection of voters
db1 = client.private  # create database
password_manager = db1.private_key # for voters priv key


def encrypt(public, input):

    encrynumber_list = [public.encrypt(x) for x in input]
    enc_temp = {}
    enc_temp['public_key'] = {'g': public.g, 'n': public.n}
    enc_temp['values'] = [(str(x.ciphertext()), x.exponent) for x in encrynumber_list]
    # return json.dumps(enc_temp)
    return enc_temp

# def get_key(url):
#     key = requests.post(url) #request a public key from the server_encrypt to encrypt the ballot
#     return json.loads(key.text) #loads public key from the server for encryptation.

def sign_comm(message, decoded):
    key = RSA.import_key(decoded) # client read private key from file. It gets key from authority. 
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(key).sign(h)
    return base64.b64encode(signature).decode('ascii')
    # app.logger.info(encoded)

def warnings(message):
    results = {"output":message}
    confirmation = json.dumps(results)
    app.logger.info(confirmation)
    return confirmation


def get_public_key_he():
    #get public key for h.e.
    url_key = 'http://server_decrypt:90/key'
    key = requests.post(url_key) #request a public key from the server_encrypt to encrypt the ballot

    llave  = json.loads(key.text) # gets public key from the server_encrypt for h.e 
    return paillier.PaillierPublicKey(n=int(llave['public_key']['n'])) # create public key obj from the key sent by the server


@app.route("/", methods=['GET','POST'])
def process():
    '''
    Client request to communicate with the unique hash (hash has name, last name and dateb) with a number id
    Server Checks if the hash value is in the server correspondent to that id. (checks if exists and it has voted yet) gets the public key correspondennt to that hash value and id, and encrypt its public Homomorphic Encription key with it (with a message). Sends to the client. Client deciphers and ciphers the ballot and deciphers the random message. Sends to server. If the two messages are the same them proced to perform operations in the encrypted dsta
    '''
    if (request.method == 'POST'):

        data = request.json

        if data:
            #checks if no selection is made
            if int(data['input']) == -1:
                return warnings("No selection")

            #checks if no id number was entered
            if data['id_num'] == "":
                return warnings("Enter a valid Id")

            #build ballot 
            vote_list = [0,0,0,0] # representation of a ballot. Each index represent a cadidate. We enforce one vote per ballot by using droplist in the frontend
            vote_list[int(data['input'])] = 1 # add 1 to the index number of the candidate choosen

            public_key_rec = get_public_key_he() #gets public key to encrypt the ballot for Homomorphic encryption
            #encrypt ballot
            ballot  = encrypt(public_key_rec, vote_list)#encrypt
            code = ballot['values']
            # app.logger.info(code) 

            # get salt from the database
            id_value = data['id_num']
            password = data['password']

            password_string= str.encode(password)  

            temp_salt = requests.post('http://password_manager:6000/salt',json = json.dumps([id_value]))#gets salt from the database to generate hash value
            salt = json.loads(temp_salt.text)
            # app.logger.info(salt)

            if salt == 1:
                return warnings("Voter no registered")

            # aunthenticate connection by ending the hashed password with salt added
            password_aunthticate = hashlib.pbkdf2_hmac('sha256', password_string, str.encode(salt), 5001)
            # app.logger.info(password_aunthticate)

            temp_private_key = requests.post('http://password_manager:6000/download',json = json.dumps([id_value, password_aunthticate.hex()])) #aunthenticate and download encrypted private key
            private_key = json.loads(temp_private_key.text)

            if private_key == 1:
                return warnings("Aunthentication failed")

            password_hash = hashlib.pbkdf2_hmac('sha256', password_string, str.encode(salt), 5000)

            decoded = cryptocode.decrypt(private_key, password_hash.hex())
            # app.logger.info(decoded)

            if not decoded:
                return warnings("Wrong password.")

            message = str(code[0][0]) + str(code[1][0]) + str(code[2][0])
            encoded = sign_comm(message, decoded) #encode the message to be sent t
            '''
            "paquete" contains the encrypted ballor, the hash, the id and the encoded message
            '''
            paquete = [ballot, data['id_num'], encoded]
            temp = requests.post('http://server',json = json.dumps(paquete))#send data to the server to be added to the tally. Data is already encrypted encrypted.
            results = json.loads(temp.text) #gets sucess or fail, depents on the results of the vote counting 

            confirmation = json.dumps(results)
            app.logger.info(confirmation)
            return confirmation


@app.route("/css/<path:filename>")
def send_file(filename):
    return send_from_directory('css', filename)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
