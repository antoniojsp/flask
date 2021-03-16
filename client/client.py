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

# helpers functions
def encrypt(public, input):

    encrynumber_list = [public.encrypt(x) for x in input]
    enc_temp = {}
    enc_temp['public_key'] = {'g': public.g, 'n': public.n}
    enc_temp['values'] = [(str(x.ciphertext()), x.exponent) for x in encrynumber_list]
    # return json.dumps(enc_temp)
    return enc_temp

def sign_comm(message, decoded): #checks integrity oof ballots
    key = RSA.import_key(decoded) # client read private key from file. It gets key from authority. 
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(key).sign(h)
    return base64.b64encode(signature).decode('ascii')

def warnings(message): # massages
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

def hash_integrity(packet):
    value = 0
    for i in packet:
        value+= int(i[0])
    
    return hashlib.pbkdf2_hmac('sha256', str.encode(str(value)), str.encode("antonio"), 5000).hex()
    # return str(value)

def generate_hashes(password, salt):
    password_string= str.encode(password)  
    a = hashlib.pbkdf2_hmac('sha256', password_string, salt.encode(), 5000) # for encrypt
    b = hashlib.pbkdf2_hmac('sha256', password_string, salt.encode(), 5001) # for aunthenticate
    return a, b

@app.route("/", methods=['GET','POST'])
def process():
    '''
    Client extract information from website. It will validate the input. It  checks the password by checking with the password manager (using hashes). The password manager will return encrypted private key for RSA signing. It will perform homomorphic encryption with the public key from "decrypt_server", sign the ballot with the RSA private key and sent it to the server. The whole part would be encrypted and the server that performs the  addition of the ballot to the tally  cannot see the voter's candidate election.
    '''
    if (request.method == 'POST'):

        data = request.json

        if data:
            
            #values extracted from the page
            id_value = data['id_num']
            password = data['password']
            input_val = int(data['input'])

            '''
            Data validators
            '''
            #checks if no selection is made
            if input_val == -1:
                return warnings("No selection")
            #checks if no id number was entered
            if id_value == "":
                return warnings("Enter a valid Id")
            #checks if  a password was provided
            if password == "":
                return warnings("No password provided.")

            '''
            Built the ballot and encrypt it
            '''
            #build ballot 
            vote_list = [0,0,0,0] # representation of a ballot. Each index represent a cadidate. We enforce one vote per ballot by using droplist in the frontend
            vote_list[input_val] = 1 # set to 1  the index number of the choosen candidate
            public_key_rec = get_public_key_he() #gets public key to encrypt the ballot for Homomorphic encryption
            ballot  = encrypt(public_key_rec, vote_list)# perform H.E encryption on the values from the list.
            '''
            Sign the ballot with the voter private key
            - get salt from the password_manager
            - hash with  the salt (5001 rounds)
            - use this hash to authe. and get encryoted priv. key
            - decrypt priv key with the hash + salt but with 5000 rounds
            - use the encrypted values of the ballloot to generate a hash and sign it with priv key
            '''
            temp_salt = requests.post('http://password_manager:6000/salt',json = json.dumps([id_value]))#gets "salt" from the password  manager database to generate the hash value.
            salt = json.loads(temp_salt.text)

            if salt == 1: # if "salt" returns 1, then there is no associeted account with the voter
                return warnings("Voter no registered")

            #generates both hashes to authe. and decrypt the password_manager encrypted key
            password_decrypt, password_aunthticate = generate_hashes(password, salt)

            # obtain the private key. sends the hashed password with salt and the id number
            auth_kit = [id_value, password_aunthticate.hex()] # data need to auuthenticate and download encrypted key
            temp_private_key = requests.post('http://password_manager:6000/download',json = json.dumps(auth_kit)) #aunthenticate and download encrypted private key
            private_key = json.loads(temp_private_key.text) # gets the encrypted privsate key or 1 if it's not successful

            if private_key == 1: # if the password_auth doesn't match inside password_manager, stop. It won't try  to decrypt
                return warnings("Authentication failed")

            decrypt_key = cryptocode.decrypt(private_key, password_decrypt.hex()) #encrypts the private key using  "password_hash"

            packet_values = ballot['values'] # extract raw encrypter ciphertext to sign up the code
            message = hash_integrity(packet_values)# created hash with the encrypted values of the ballot.
            encoded = sign_comm(message, decrypt_key)  #sign the message to perform integrity verificatin

            '''
            "Paquete" contains the encrypted  ballot, the voter's id and the signature to check integrity
            This is the step where it's sent to the server
            '''

            paquete = [ballot, data['id_num'], encoded] #forms list with the parts to be sent.
            temp = requests.post('http://server',json = json.dumps(paquete))#send data to the server to be added to the tally. Data is already encrypted encrypted.

            '''
            Get an answer from the server if it was successful or not
            '''
            results = json.loads(temp.text) #gets sucess or fail, depents on the results of the vote counting 
            confirmation = json.dumps(results)
            app.logger.info(confirmation)
            return confirmation


@app.route("/css/<path:filename>")
def send_file(filename):
    return send_from_directory('css', filename)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
