
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
#RSA
import binascii
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

import hashlib

#random values
from random import seed
from random import random

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

'''
It look up in the "register" database for the vooter's public key and "has_voted" booolean.
'''
def search_voter_registration(id: str):

    for i in voters_info.find({'id':id}):# look up for the public key in the Authority database
        pub_key = i['pk']
        has_voted = i['has_voted']

    return pub_key, has_voted

       
# gets from the decrypt_server the private key to perform homomorphic encryption/ additin
def get_public_he():
    #get public key for h.e.
    url_key = 'http://server_decrypt:90/key'
    key = requests.post(url_key) #request a public key from the server_encrypt to encrypt the ballot

    llave  = json.loads(key.text) # gets public key from the server_encrypt for h.e 
    return paillier.PaillierPublicKey(n=int(llave['public_key']['n'])) # create public key obj from the key sent by the server

# returnn personalized messages for ajax
def warnings(message):
    results = {"output":message}
    confirmation = json.dumps(results)
    app.logger.info(confirmation)
    return confirmation

# generates hash values from the ballot encrypted ciphertext to verify integrity
def hash_integrity(packet):
    value = 0
    for i in packet:
        value+= int(i[0])

    result = hashlib.pbkdf2_hmac('sha256', str.encode(str(value)), str.encode("antonio"), 5000).hex()
    return result


# checks for the integrity of the signature of the packet sent by the client
def check_signature_integrity(voter_public_key, value_hash, encrypted_message ):

    key = RSA.import_key(voter_public_key)
    h = SHA256.new(value_hash.encode())
    decoded = base64.b64decode(encrypted_message)

    pkcs1_15.new(key).verify(h, decoded)
    app.logger.info("The signature is valid.")
    return True



def hash_audit(values):
    sum = 0
    seed(1)
    salt_random = str(random()) #random salt to create unique hash for audit
    for i in values:
        sum+=int(i)

    temp_hash= str.encode(str(sum))  
    return hashlib.pbkdf2_hmac('sha256', temp_hash, salt_random.encode(), 5000).hex() # for audit

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
            package = vote_encrypted[0]['values'] # encrypted values ciphertext that conntins the  encrypted ballot. It is also use to form the hash to check integrity and detect  tampering
            encrypted_hash = vote_encrypted[2] # signed hash to be compared with the encripted message generated for the server

            '''
            encrypted_message is a message signed with the private key of the client and verify with the public key that the server has. The server look up for the public key in the database using the id of the voter. Mensaje is extracted from the "package" and after the encrypted message is decrypted, it is compare with "mensaje" and checks if they are equal.
            '''

            if voters_info.count_documents({ "id": id_value }, limit = 1) != 0: # checks if the voter has been already register. NOTE: it's safe to assume that if a ballot reach this point, the voter existes since the client perform a pre-screening

                voter_public_key, has_voted = search_voter_registration(id_value) #gets from the voter database the public key 

                value_hash = hash_integrity(package)

                if has_voted == True: # user has already cast a vote
                    app.logger.info("voter already voted")
                    return warnings("Error. Vote already casted for this voter.")

                try:
                    check_signature_integrity(voter_public_key, value_hash, encrypted_hash)
                    app.logger.info("Good signature")
                except:
                    app.logger.info("Possible tampering") # when there is a problem with the integrity of the signature, a modification can be assumed.
                    return warnings("Error. Possible vote tampering.")

                '''
                Gets public key from the decrypt_server and transform it to an object. It is used to transform the ciphertext of the current tally into EncryptedNumber objects that can perform addition with encrypted data
                '''
                public_key_rec = get_public_he() #server_decrypt holds private and public key, here the public key is obtanained

                '''
                Encrypted ballot is sent from the client in ciphertext. With the public key, this ciphertext is transformed in EncryptedNumber with H.E properties. THis contains the encrypted ballot.
                '''
                vote_received_enc = [paillier.EncryptedNumber(public_key_rec, int(x[0]), int(x[1])) for x in package] # convert the cipher values oof the ballot  to objects.

                '''
                Extract from the election database the current tally and transform the ciphertext into encryptednumber objects with encrypted information of the tally that can perform additions.
                '''
                tally_mongo_encrypted = [i for i in tally_votes.find()] # gets tally from database
                encriptado_temp = [paillier.EncryptedNumber(public_key_rec, int(j)) for j in tally_mongo_encrypted[len(tally_mongo_encrypted)-1]["votes"]] # gets the current tally values that are record in the db. Convert those values in EncryptedNumber objects. (Current values is last )

                '''
                Perform an addition between the tally and the  ballot. Update tally
                '''
                add_vote(encriptado_temp, vote_received_enc) # add the ballot to the tally
                cipher_values = [str(i.ciphertext()) for i in encriptado_temp] # creates list with the ciphertext to be stored in mongodb

                verification_hash = hash_audit(cipher_values)
                app.logger.info(verification_hash)

                '''
                Insert the  updated tally to the election database
                '''
                try:
                    tally_votes.insert_one({"votes":cipher_values, "verification_hash":verification_hash}) # insert value to
                except:
                    '''
                    If for any reason, writting the ballot fails, it stops anything else and return error. No roll back needed
                    '''
                    message = "Error. Updated tally where not registered correctly. Try again"
                    app.logger.info(message)
                    return warnings(message)
                '''
                Update the information of the elector's database. Delete the public key to avoid make extra sure that a person cannot vote twice.
                '''
                try:
                    voters_info.update_one({'id':id_value}, {"$set":{"has_voted":True, "pk":""}})
                except:
                    '''
                    If updating the information of the voters fails for any reason (update the voters "has_voted" is not set to true) then it rolls back the vote just entered and ask to try again.
                    '''
                    message = "Error. The voter's status couldn't be updated. Rolling back vote. Try  again"
                    votes_list = [i for i in tally_votes.find()]
                    tally_votes.delete_one({'_id':votes_list[-1]["_id"]})
                    app.logger.info(message)
                    return warnings(message)


                temp = {}
                temp['output'] = "Success! For audit, please keep this code: " + verification_hash # confirmation. If gets to this point we can assume the vote has been registered correctly

            else:
                app.logger.info("Voter is not registered!")
                return warnings("Failure! Voter is not registered.")

        except:
            temp = {}
            temp['output'] = "Failure! Error in server." # confirmation
            
        results = json.dumps(temp)
        return results

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80, debug=True)
