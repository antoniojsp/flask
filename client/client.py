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

app = FlaskAPI(__name__)
cors = CORS(app, resources={r'/*': {"origins": '*'}})

'''
Client encrypts the ballot
'''
def encrypt(public, input):
    app.logger.info("funcion")
    encrynumber_list = [public.encrypt(x) for x in input]
    enc_temp = {}
    enc_temp['public_key'] = {'g': public.g, 'n': public.n}
    enc_temp['values'] = [(str(x.ciphertext()), x.exponent) for x in encrynumber_list]
    # return json.dumps(enc_temp)
    return enc_temp


@app.route("/", methods=['GET','POST'])
def process():
    '''
    Client request to communicate with the unique hash (hash has name, last name and dateb) with a number id
    Server Checks if the hash value is in the server correspondent to that id. (checks if exists and it has voted yet) gets the public key correspondennt to that hash value and id, and encrypt its public Homomorphic Encription key with it (with a message). Sends to the client. Client deciphers and ciphers the ballot and deciphers the random message. Sends to server. If the two messages are the same them proced to perform operations in the encrypted dsta
    '''
    if (request.method == 'POST'):

        data = request.json

        if data:

            vote_list = [0,0,0,0] # representation of a ballot. Each index represent a cadidate. We enforce one vote per ballot by using droplist in the frontend
            
            if int(data['input']) == -1:
                results = {"output":"No selection"}
                confirmation = json.dumps(results)
                app.logger.info(confirmation)
                return confirmation

            vote_list[int(data['input'])] = 1 # add 1 to the index number of the candidate choosen
            key = requests.post('http://server_decrypt:90/key') # request a public key from the server_decrypt to encrypt the ballot
            llave  = json.loads(key.text) # gets public key from the server_encrypt for encryptation 
            public_key_rec = paillier.PaillierPublicKey(n=int(llave['public_key']['n'])) # create public key obj from the key sent by the server

            ballot  = encrypt(public_key_rec, vote_list)
            code = ballot['values']

            # codigo = str(code[0][0]) + str(code[1][0]) + str(code[2][0]) 
            # app.logger.info(codigo)


            '''
            TEMP:
            Sign communications
            '''
            message = str(code[0][0]) + str(code[1][0]) + str(code[2][0])
            key = RSA.import_key(open('private.pem').read()) # client read private key from file. It gets key from authority. 
            h = SHA256.new(message.encode())
            signature = pkcs1_15.new(key).sign(h)
            encoded = base64.b64encode(signature).decode('ascii')

            '''
            "paquete" contains the encrypted ballor, the hash, the id and the encoded message
            '''
            paquete = [ballot, data['hash'], data['id_num'], encoded]
            
            temp = requests.post('http://server',json = json.dumps(paquete))#send data to the server to be added to the tally. Data is already encrypted encrypted.
            results = json.loads(temp.text) #gets sucess or fail, depents on the results of the vote counting 

            confirmation = json.dumps(results)
            app.logger.info(confirmation)
            return confirmation


# @app.route("/css/<path:filename>")
# def send_file(filename):
#     return send_from_directory('css', filename)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
