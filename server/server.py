from typing import Collection
from phe import paillier
import json
from random import *
from flask import request, url_for, flash
from flask_api import FlaskAPI, status, exceptions
#mongodb
import pymongo # modules
from pymongo import MongoClient
import os
import requests
#date
from datetime import datetime
#RSA
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii
import base64
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

'''
server.py connects with client.py and gets the encrypted ballot and perform the addition of the vote into the tally. It gets the public key from server_decrypt.py and does not handle the private key since we don't want to have the chance of having both keys in the same location in this server since there is sensitive data.
'''

app = FlaskAPI(__name__)

app.secret_key = "temporal location"

'''
Connects with atlas db to stores values
'''
client = MongoClient("mongodb+srv://antonio:antonio@cluster0.hb8y0.mongodb.net/experiment?retryWrites=true&w=majority", ssl=True,ssl_cert_reqs='CERT_NONE')
db = client.election  # create database
collection = db.vote # for votes

db1 = client.register  # create database
collection1 = db1.voter

# count = 0   
'''
add_vote(tally_encrypt:list, vote_received_encrypt:list) function
    tally_encrypt => current total tally encrypted extracted from mongodb
    vote_received_encrypt => ballot with one elector vote (encrypted)

it add up the values from the current tally with the ballot. A ballot has values from 0 to 1, 1 represents the candidate election (depends on the index). All the information is encrypted and uses the properties of homorphic encryption to perform addition.
'''
def add_vote(tally_encrypt:list, vote_received_encrypt:list):#send public key to the client to encrypt the ballot

    for i in range(len(tally_encrypt)): #perform an addition bewtween the value in the tally and the value in the vote (same position indicates same candidate)
        tally_encrypt[i]+= vote_received_encrypt[i]

'''
Handles the process to add a vote to the tally

A ballot is recorded by the client in the form of a list, I.E [0,0,0,1], this example means that the fourth candidate has been selected. The client encrypt the values of this array and send it to the server. The properties of homomorphic encryption allows perform additions and multiplications without decrypting the information. We perform the addition here and then transform the EncryptedNumber objects into ciphertext to be stored in mongodb.
'''
@app.route("/", methods=['POST'])
def process():
    '''
    Workflow:
    - Gets request from the client through Ajax
    - The data contains the encrypted ballot and the hash value.
    - hash value look up in the database. Verify if is registered and has not voted

    '''
    if request.method == 'POST':

        vote_encrypted = json.loads(request.data) # gets the encrypted ballots from the client
        try: # in case of failure, returns an output with the message "Failure", otherwise, "Success

            encrypted_message = vote_encrypted[3]
            id_value = vote_encrypted[2]
            package = vote_encrypted[0]['values']

            mensaje = str(package[0][0]) + str(package[1][0]) + str(package[2][0])

            for i in collection1.find({'id':id_value}):
                voter_key = i['pk']

            # if voter_key != None:
            #     app.logger.info("MMMMMM")

            if collection1.count_documents({ "id": id_value }, limit = 1) != 0: # checks if the voter has been already register.
                 app.logger.info("MMMMMM")

            



            try:
                key = RSA.import_key(voter_key)
                h = SHA256.new(mensaje.encode())

                decoded = base64.b64decode(encrypted_message)
                try:
                    pkcs1_15.new(key).verify(h, decoded)
                    good_key = True
                    app.logger.info("The signature is valid.")
                    flash("The signature is valid.")
                except (ValueError, TypeError):
                    app.logger.info("The signature is not valid.")
                    good_key = False
                    temp = {}
                    temp['output'] = "Failure! Bad Key." # confirmation
                    results = json.dumps(temp)
                    flash("Failure! Bad Key.")
                    return results
            except:
                app.logger.info("Voter is not registered!")
                good_key = False
                flash("Voter is not registered!")
                temp = {}
                temp['output'] = "Failure! Voter is not registered." # confirmation
                results = json.dumps(temp)
                return results

            for i in collection1.find({'id':id_value}):
                has_voted = i['has_votes']
            
            app.logger.info(has_voted)

            if has_voted == True:
                temp = {}
                temp['output'] = "Failure! Voter has alerady voted." # confirmation
                flash("Failure! Voter has alerady voted.")
                results = json.dumps(temp)
                return results

            #gets the public key from the decryption server.
            key = requests.post('http://server_decrypt:90/key') #request a public key from the server_encrypt to encrypt the ballot
            llave  = json.loads(key.text) #loads public key from the server for encryptation. 

            public_key_rec = paillier.PaillierPublicKey(n=int(llave['public_key']['n']))#create public key obj from the key sent by the server

            vote_received_enc = [paillier.EncryptedNumber(public_key_rec, int(x[0]), int(x[1])) for x in vote_encrypted[0]['values']] # convert the cipher values received front the 

            tally_mongo_encrypted = [i for i in collection.find()]

            encriptado_temp = [paillier.EncryptedNumber(public_key_rec, int(j)) for j in tally_mongo_encrypted[len(tally_mongo_encrypted)-1]["votes"]] # gets the current tally values that are record in the db. Convert those values in EncryptedNumber objects. (Current values is last )

            add_vote(encriptado_temp, vote_received_enc) # add the ballot to the tally
            cipher_values = [str(i.ciphertext()) for i in encriptado_temp] # creates list with the ciphertext to be stored in mongodb

            now = datetime.now()
            timestamp = datetime.timestamp(now)

            collection.insert_one({"timestamp":now, "votes":cipher_values}) # insert value to
            collection1.update_one({'id':id_value}, {"$set":{"has_votes":True}})
            temp = {}
            temp['output'] = "Success!" # confirmation
            flash("Success!")

        except:
            temp = {}
            temp['output'] = "Failure! Error in server." # confirmation
            flash("Failure! Error in server.")
            
        results = json.dumps(temp)
        return results

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80, debug=True)
