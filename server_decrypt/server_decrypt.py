from phe import paillier
import json
from random import *
# flask modules
from flask import request, url_for
from flask_api import FlaskAPI, status, exceptions
# pymongo modules
import pymongo # modules
from pymongo import MongoClient

import os
import pickle


app = FlaskAPI(__name__)

'''
Connects with atlas db to stores values
'''

client = MongoClient("mongodb+srv://antonio:antonio@cluster0.hb8y0.mongodb.net/experiment?retryWrites=true&w=majority", ssl=True,ssl_cert_reqs='CERT_NONE')
db = client.election  # create database or connect
collection = db.vote
number_votes =  db.number

'''
The commented section down here is used to create a pair of keys for H.E.
I am using pickle to save the objects (pub key and priv key) and re use it after each restart
'''
# public_key_server, private_key_server = paillier.generate_paillier_keypair()#keys from the server. We send the public key to the client to encrypt the ballot and also to the server to perform the calculations necessary. We keep the private key here to perform the decryption to get the results

# with open('key', 'wb') as output:
#     pickle.dump(public_key_server, output, pickle.HIGHEST_PROTOCOL)

#     pickle.dump(private_key_server, output, pickle.HIGHEST_PROTOCOL)

# del public_key_server
# del private_key_server

with open('key', 'rb') as input: # pull the pair of keys froom the main folder
    public_key_server = pickle.load(input)
    private_key_server = pickle.load(input)

'''
Send a the public key to the client so it can encrypt the vote to be transmited to the server securely
'''
@app.route("/key", methods=['POST'])
def key(): # send public key to the client to encrypt the ballot
    if request.method == 'POST':
        key = {}
        key['public_key'] = {'g': public_key_server.g, 'n': public_key_server.n} # values necessary to create a public key object in the client
        return json.dumps(key)

'''
Decrypt the results from the database and sends it to be displayed
'''
@app.route("/results", methods=['POST'])
def results():

    if request.method == 'POST':
        tally_mongo_encrypted = [i for i in collection.find()]
        encriptado_temp = [paillier.EncryptedNumber(public_key_server, int(j)) for j in tally_mongo_encrypted[len(tally_mongo_encrypted)-1]["votes"]] # gets the current tally values that are record in the db. Convert those values in EncryptedNumber objects. (Current values is last )
        temp = {}
        temp['output'] = [private_key_server.decrypt(x) for x in encriptado_temp]  # decrypt values to be shown.

        return json.dumps(temp)

'''
Dropt the "election" database and created a new list of zeros ([0,0,0,0]), encryptsit with the public key  and sents it back to the database to reset the results
'''
@app.route("/new", methods=['POST'])
def new():#restart tallies to zero

    if request.method == 'POST':
        collection.delete_many({})# drop database
        nuevo = [str(public_key_server.encrypt(0).ciphertext()) for i in range(0,4)]#list lenght number of candidates        

        collection.insert_one({"votes":nuevo})# insert new tally with zeros encrypted
        return



if __name__ == "__main__":
    app.run(host='0.0.0.0', port=90, debug=True)
