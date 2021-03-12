
# from typing import Collection
#Pallier Homomorphic Encryption Library
from phe import paillier
#flask
# from random import *
import json
import requests
from flask import request, url_for
from flask_api import FlaskAPI, status, exceptions
#mongodb
import os
import pymongo # modules
from pymongo import MongoClient
#date
from datetime import datetime
#RSA
import binascii
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

'''
server.py connects with client.py and gets the encrypted ballot and perform the addition of the vote into the tally. It gets the public key from server_decrypt.py and does not handle the private key since we don't want to have the chance of having both keys in the same location in this server since there is sensitive data.
'''

app = FlaskAPI(__name__)

'''
Connects with atlas db to stores values
'''
client = MongoClient("mongodb+srv://antonio:antonio@cluster0.hb8y0.mongodb.net/experiment?retryWrites=true&w=majority", ssl=True,ssl_cert_reqs='CERT_NONE')
db = client.election  # create database
tally_votes = db.vote # for votes

db1 = client.register  # create database
voters_info = db1.voter

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

def search_voter_registration(id: str):

    for i in voters_info.find({'id':id}):# look up for the public key in the Authority database
        pub_key = i['pk']
        has_voted = i['has_votes']

    return pub_key, has_voted

def get_key(url):
    key = requests.post(url) #request a public key from the server_encrypt to encrypt the ballot
    return json.loads(key.text) #loads public key from the server for encryptation.
                
def get_public_he():
    #get public key for h.e.
    url_key = 'http://server_decrypt:90/key'
    key = requests.post(url_key) #request a public key from the server_encrypt to encrypt the ballot

    llave  = json.loads(key.text) # gets public key from the server_encrypt for h.e 
    return paillier.PaillierPublicKey(n=int(llave['public_key']['n'])) # create public key obj from the key sent by the server

def warnings(message):
    results = {"output":message}
    confirmation = json.dumps(results)
    app.logger.info(confirmation)
    return confirmation

'''
Handles the process to add a vote to the tally

A ballot is recorded by the client in the form of a list, I.E [0,0,0,1], this example means that the fourth candidate has been selected. The client encrypt the values of this array and send it to the server. The properties of homomorphic encryption allows perform additions and multiplications without decrypting the information. We perform the addition here and then transform the EncryptedNumber objects into ciphertext to be stored in mongodb.
'''
@app.route("/", methods=['POST'])
def process():
    '''
    Workflow:
    - Gets request from the client through Ajax
    - The data contains the encrypted ballot, id, hash.
    - id value look up in the database. Verify if is registered and has not voted. 
    - Client send encrypted message with the private key. The server look up the id in the database and returns the public key already registered
    '''

    if request.method == 'POST':
        vote_encrypted = json.loads(request.data) # gets encrypted ballot, id and secret mesage.
        try: # in case of failure, returns an output with the message "Failure", otherwise, "Success
            id_value = vote_encrypted[1] # id of the voter
            package = vote_encrypted[0]['values'] # encrypted values ciphertext to be used to check if the  message comes from the owner of the private key.
            
            '''
            encrypted_message is a message encrypted with the private key of the client and decrypt with the public key that the server has. The server look up for the public key in the database using the id of the voter. Mensaje is extracted from the "package" and after the encrypted message is decrypted, it is compare with "mensaje" and checks if they are equal.
            '''

            mensaje = str(package[0][0]) + str(package[1][0]) + str(package[2][0]) # message used to compare with the secret message from the client. Equal messages auntheticate the client
            encrypted_message = vote_encrypted[2] # encrypted message to be compared with the encripted message generated for the server

            if voters_info.count_documents({ "id": id_value }, limit = 1) != 0: # checks if the voter has been already register.
                
                voter_key, has_voted = search_voter_registration(id_value)

                if has_voted == True: # user has already cast a vote
                    return warnings("Failure! Voter has already voted.")

                # deciphering message from client. Client used its private key and Server use the public key storage in its database
                key = RSA.import_key(voter_key)
                h = SHA256.new(mensaje.encode())
                decoded = base64.b64decode(encrypted_message)
                # app.logger.info(decoded)

                try:
                    pkcs1_15.new(key).verify(h, decoded)
                    good_key = True
                    app.logger.info("The signature is valid.")
                except (ValueError, TypeError):
                    app.logger.info("The signature is not valid.")
                    return warnings("Failure! Bad Key.")

                '''
                Gets public key from the decrypt_server. It is used to encrypt ballots
                '''
                public_key_rec = get_public_he() #server_decrypt holds private and public key

                vote_received_enc = [paillier.EncryptedNumber(public_key_rec, int(x[0]), int(x[1])) for x in vote_encrypted[0]['values']] # convert the cipher values received front the 
                tally_mongo_encrypted = [i for i in tally_votes.find()] # gets tally from database

                encriptado_temp = [paillier.EncryptedNumber(public_key_rec, int(j)) for j in tally_mongo_encrypted[len(tally_mongo_encrypted)-1]["votes"]] # gets the current tally values that are record in the db. Convert those values in EncryptedNumber objects. (Current values is last )

                add_vote(encriptado_temp, vote_received_enc) # add the ballot to the tally
                cipher_values = [str(i.ciphertext()) for i in encriptado_temp] # creates list with the ciphertext to be stored in mongodb
                
                tally_votes.insert_one({"timestamp":datetime.timestamp(datetime.now()), "votes":cipher_values}) # insert value to

                voters_info.update_one({'id':id_value}, {"$set":{"has_votes":True}})
                temp = {}
                temp['output'] = "Success!" # confirmation

            # else:
            #     app.logger.info("Voter is not registered!")
            #     # good_key = False
            #     # temp = {}
            #     # temp['output'] = "Failure! Voter is not registered." # confirmation
            #     # results = json.dumps(temp)
            #     return warnings("Failure! Voter is not registered.")

        except:
            temp = {}
            temp['output'] = "Failure! Error in server." # confirmation
            
        results = json.dumps(temp)
        return results

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80, debug=True)
