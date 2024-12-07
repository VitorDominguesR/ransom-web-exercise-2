# ransom-c2-exercicio-2

```python -m venv .venv```

```source .venv/bin/activate```

```pip install -r requirements.txt```

```python manage.py makemigrations```

```python manage.py migrate```

```python manage.py runserver```


## Examples

```$ curl --location 'http://127.0.0.1:8000/key' --header 'api-key: secretkey'```
```bash
curl --location 'http://127.0.0.1:8000/receive' \
--header 'api-key: secretkey' \
--header 'Content-Type: application/json' \
--data '{
    "key": "PJrrZQHum3y/+ifdh/ZQ7Ry+E3n0vgmgAmkq+OMbOHih1cEci8Ieu97DYDVzy4ANRb2Epr2U8zVX+I4MguNky5uCxr2nhyYJe5MoqIVnOYfWRic9txsI1q7g9qNy8nIReK0sNMUQWjOhu2SsmcjPUBd1Xi0I7BVoG8KqGhNpLGgVqfET0UMJ2XV6+op/bF6JBqhMwxQfD/CxqSg3rOLSb++HmnFi47kzozOas+ounpqqzJvrSFB8XrVbybl1joGdL+wnNqniKxZ+zkSaeEuDjRoytwCHJkTsNFA6L5uswORIqWAEvNFqoAubhXnGWC9hXTlAnKsUbCjcEHk8O0RZMA==",
    "uuid": "d1cb47da-a4fa-4587-8574-9e5d07a4d426"
}'
```

```key -> base64(encrypt_pub_key(simetric_key))``

- Check key from uuid

```bash
curl --location 'http://127.0.0.1:8000/key?uuid=a14ad9c5-9351-4102-b044-9b855c2d5d41' \
--header 'api-key: secretkey'
```

## Encrypt and Decrypt

```python
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
```