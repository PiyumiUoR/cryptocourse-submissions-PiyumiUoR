# Task 1

## Task 1.1

Used commands:
1. Generation of key

```terminal
openssl genpkey -out test.key \
-algorithm RSA \
-pkeyopt rsa_keygen_bits:2048 \
-aes-128-cbc
```

2. Public key generation
```terminal
openssl pkey -in test.key -pubout -out test-public.key
```

3. Encryption using `rsa`
```terminal
openssl pkeyutl -encrypt -inkey test-public.key -pubin -in text.txt -out test-enc.enc
```

Command line outputs:
```terminal
arch@archlinux ~/Documents/crypto/ex5 % openssl genpkey -out test.key \
-algorithm RSA \
-pkeyopt rsa_keygen_bits:2048 \
-aes-128-cbc
.........+.....+....+...+......+++++++++++++++++++++++++++++++++++++++*....+.+...+++++++++++++++++++++++++++++++++++++++*................+...........+....+..+....+...........+...+.+..............+....+..+...+.+.........+.....+...............+.............+..+......+.+.........+..+.......+............+......+..................+..+............+.+......+......+.....+....+.....+.........+.........+.+...........+.+........+.++++++
..+..........+..+.......+++++++++++++++++++++++++++++++++++++++*.+++++++++++++++++++++++++++++++++++++++*.....+..............+....+......+.........+..+...+.+..+.......+...+..+.......+...............+......+.....+.......+........+....+.....+.+.....+...+.........+.+.........+........+...+.+......+............+..+.........+......+...+..........+.....+.......+.....+......+.......+...+...+......+...+..+...+.+.................+...+....+...+..+.............+..............+.+..............+.............+.....+.+.........+.....+.+..+...+.......+.....+.......+....................+.+..+.........+.+.....+...+....+..+.+...+..+...+.........+..........+...........+..........+.....+.......+...+......+...........+...+.+..........................+.......+...+..................+..+....+...........+...+................+.....+....++++++
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
arch@archlinux ~/Documents/crypto/ex5 % cat test.key       
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQjXzVNzkHib05HIaH
BYDztwICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEAQIEEKnhqEPi5lKZ4LX4
2sJNElcEggTQU/37jiJM5n4hZ1K4ySpoiTTAI+dp29abLEsSA6dgISv5zSmIUq2N
WGvHZ8+X2p7MxPJu6j6V5DHxKIJa6PGUxckZgQyYTzDSW0mjvQniVt5IC551jDGc
ZDXb22hmqyxmMbfuj58/Kz/tu3XGg3EkLFKT44dFbEHBtqfkzLfzHM8M04veMXIC
Xm3YIA8KE3PjwJDpd+NSUsw05KdcE4m5eJzoC+U5f+xE7LbvbFQ74Gai+4SNB7Yj
k7IBIjjQ1gNtXzL4ZViExnToyLghr6QUsS5g9pofUVnSzAk2TQ0QWbggejuuee9M
CGN+/o/fSn3z8tY9i5k4QuM2GFNq58haIGt4P8bp173FxB8RgtbA2azRgacIXvkw
AJyu/yRpHsiJh+rZzXybAycv8H29uJrPQSHWcQBeS2W1HfxF3dx5pY6cPpgf9Ocn
UOMRv8xUI1cqZyD0Z1zHnIk7nA5T3v5Qr4kTy8nTjHiO7BoXM0YqOEboWtZvEgWU
IrLy7WOxGjj44tD33/S+6F5F8n2dxHBnUe43n7UW9BoH9d83HvvWoHeHM/63ZDL1
fYpIG/i8GUD31DLkuosPQFHmggKexYLjDPN1D8EPFl0W4wNv6tRYMBXBZoKAy1Ow
Xfn2k+NeRpyv9z8lwvGN40Gszw5Hfl10WV/oLc0KBGLGK9e9Wbt0pegmfRtKqLZK
MUa3eBObXtNp8PyoTyMvGf+wuunZ0dDxc+MnUPwzfMooY+AycgZ4Mj0ODFair+8n
0dM5mNWVs2ANYPI9C9lrXixQFGoSM4GIsCI5UWm3yxscuw13wLFRF3Qq48lIlQgY
mYP2tLLJekmb2wX657fZz2QM6XwP22UEm+f8dJy3kCvrCcyNQwOEQ72/FCTb94fJ
9UNd4MLPRKBrkKwOmx/IaEsn7kSnpUpKY0pBbByJeVmf/89JnJ6q9bW6POY0dZse
PSzW8QZbo/5gcvo2FlVZZjFzJOHiEsgMRInlW6Jb84neYVWS8zDcw6qwIKfVqBvN
iMZC6ofMwKeKadoiyHBJQOPdou0e67VpYIt3fhZls/oq2KgGM7JFHbN3xS5Onixj
XDAF1Xfqm7247A0R66wNVGqHfaYNVb0o5OmtRcayOHmcUNSXwE698lq2FwSGPOc+
kVbTN3/0LwrAdKNrDKxLcj2xHbyUQ22u8NUIZRm+kjep9qK3qv4y5ipTIg08k4vL
8l5rqrla8eb4z3+SUR8qKV6inWMviM7R6ebAXKmeMDauZDPXyxTEgo2OIfTWiYB1
AkT02Dppo3cvpRiEuIoF48X4SczNQO56RBqXCo8TcmCt4FS03MnSU2o+y+gYYDNb
5/dqoTCIDLOC3lpX0PulFvj5N6ZVjzVt6yhzaZfP7KjEy0BMCH18f7WfaAWJk9Vm
qarSkJ6vB33mbPRJ8Cr3mE4gsT2KYLQRsiD+i+BUDpE4FUFhU21PHsQIwrpPUKnU
2nILkRbyiGZxTEq+UVKB+hzvwDYddfeHzNnNix2jgl2nEvyQ5fA1tqZzwDuKomCA
98S+UP8AdvbJJWvLWudDcUGNpj+rK2dKyhka9deegIemHjXuO58lxdLFSuMg1nCe
gzKU6KlROw3UjU0mMM+T+YbAipWO0NVX3gANhpGzY9GXii5RhhtPBZc=
-----END ENCRYPTED PRIVATE KEY-----
arch@archlinux ~/Documents/crypto/ex5 % openssl pkey -in test.key -pubout -out test-public.key
Enter pass phrase for test.key:
arch@archlinux ~/Documents/crypto/ex5 % cat test-public.key
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApgRpu7pafdCoaeAVvjCG
o+vn7NhYj4aGJBfX+a+eJRu9TqhI1cqxSl/8sh/VXrT/vk/pki4n47NYzZlFOqD0
4kMtSXH5avOVFc3KWGTbonZSy5Aaky9mH+ALdRlQ3BRM4NUwsIRem3yogDKyFkQX
R5hndzYnn/XzzDsMWwQEZpa6yNeUm2Z9+CTPRlF+Tahe+pHp8LDRvh7Pgq893Xrh
OwJpRBedwmlJSyRIQfV6PrD4WuKmORehIKY4DbAenIuccHC4n2F3GTLORkBsd6x7
9reJje0oMGnjmqr9feuZLp20F3shmNbtFvkf2Ap+YL+i2hRPJ+0jOWQvepYZELDg
cQIDAQAB
-----END PUBLIC KEY-----
arch@archlinux ~/Documents/crypto/ex5 % openssl pkeyutl -encrypt -inkey test-public.key -pubin -in text.txt -out test-enc.enc

arch@archlinux ~/Documents/crypto/ex5 % 
```

## Task 1.2

I used SHA256 hash as the hashing algorithm. 

```terminal
openssl dgst -sha256 -sign test.key -out sign-text.sha256 text.txt
```

Public key, message and the signature:

![image1](images/image1.png)

# Task 2

## Task 2.1

I used `cryptography` library to match the keys with the messages. The code is as follows. 

```py
import os
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

signaturefolder = "./files/signatures"
publickeysfolder = "./files/public_keys"
textfilefolder = "./files/messages.txt"  

signatures = []
for filename in os.listdir(signaturefolder):
    with open(os.path.join(signaturefolder, filename), 'rb') as file:
        signatures.append(file.read())

public_keys = []
for filename in os.listdir(publickeysfolder):
    with open(os.path.join(publickeysfolder, filename), 'rb') as file:
        public_keys.append(file.read())

with open(textfilefolder, 'r') as text_file:
    for line_number, line in enumerate(text_file, start=1):
        message = line.encode('utf-8').strip()  
        
        for sig_idx, signature in enumerate(signatures):
            for pubkey_idx, public_key_data in enumerate(public_keys):
                try:
                    public_key = load_pem_public_key(public_key_data, backend=default_backend())
                    try:
                        public_key.verify(
                            signature,
                            message,
                            padding.PKCS1v15(),
                            hashes.SHA256()
                        )
                        print(f"Match found for line number {line_number}! Signature {sig_idx+1} and public key {pubkey_idx+1}.")
                    except InvalidSignature:
                        pass
                except Exception as e:
                    print(f"Error processing signature {sig_idx+1} and public key {pubkey_idx+1}: {e}")

```

The output with possible guesses is:

![image2](images/image2.png)

|Message row|Public key(s)|Signature file(s)|
--- | --- | --- 
|1   |public_key1.pem|signature20.pem|
|2   |public_key5.pem|signature14.pem|
|3   |public_key2.pem|signature4.pem|
|4   |public_key3.pem|signature6.pem|
|5   |public_key5.pem|signature9.pem|
|6   |public_key2.pem|signature2.pem|
|7   |public_key4.pem|signature10.pem|
|8   |public_key1.pem|signature17.pem|
|9   |public_key3.pem|signature12.pem|
|10  |public_key4.pem|signature8.pem|
|11  |public_key3.pem|signature1.pem|
|12  |public_key3.pem|signature3.pem|
|13  |public_key1.pem|signature16.pem|
|14  |public_key1.pem|signature5.pem|
|15  |public_key2.pem|signature15.pem|
|16  |public_key4.pem|signature11.pem|
|17  |public_key5.pem|signature13.pem|
|18  |public_key5.pem|signature19.pem|
|19  |public_key4.pem|signature7.pem|
|20  |public_key2.pem|signature18.pem|

I checked the multiple matches separately. 

```py
import os
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

signaturefolder = "./files/signatures"
publickeysfolder = "./files/public_keys"
textfilefolder = "./files/messages.txt"  

signatures = []
for filename in os.listdir(signaturefolder):
    with open(os.path.join(signaturefolder, filename), 'rb') as file:
        signatures.append(file.read())

public_keys = []
for filename in os.listdir(publickeysfolder):
    with open(os.path.join(publickeysfolder, filename), 'rb') as file:
        public_keys.append(file.read())

with open(textfilefolder, 'r') as text_file:
    for line_number, line in enumerate(text_file, start=1):
        message = line.encode('utf-8').strip()  
        
        matched_public_keys = set()
        
        for sig_idx, signature in enumerate(signatures):
            for pubkey_idx, public_key_data in enumerate(public_keys):
                try:
                    public_key = load_pem_public_key(public_key_data, backend=default_backend())
                    try:
                        public_key.verify(
                            signature,
                            message,
                            padding.PKCS1v15(),
                            hashes.SHA256()
                        )
                        matched_public_keys.add(pubkey_idx) 
                    except InvalidSignature:
                        pass
                except Exception as e:
                    print(f"Error processing signature {sig_idx+1} and public key {pubkey_idx+1}: {e}")
        
        if len(matched_public_keys) > 1:
            print(f"Match found for line number {line_number}. Signatures matched with public keys: {matched_public_keys}")

```

There is one text where the multiple matches of public keys. Output is as follows:

![image3](images/image3.png)

## Task 2.2

The RSA in textbooks does not use padding. It is susceptible to decryption-based padding oracle attacks. Textbook RSA is susceptible to chosen plaintext attacks in the absence of sufficient padding. In these attacks, the attacker selects plaintexts and looks at the related ciphertexts to obtain information about the private key.

Because textbook RSA signatures are changeable, an attacker can alter the signature and have it still be accepted as genuine.

Textbook RSA does not take into account current key length recommendations. RSA is susceptible to brute-force assaults because of its short key length, especially in light of the development of powerful computational resources.

When creating primes and key pairs, extbook RSA does not enforce the necessary standards for randomness, which could result in keys and signatures that are predictable.

Textbook RSA is hard to reason about its security features because it lacks the thorough security proofs that contemporary padding schemes like PKCS#1v1.5 or OAEP provide.

# Task 3

Message I gave for signing: `_n negative/neutral message`

The sign message:

![Signed message](images/image4.png)

```terminal
arch@archlinux ~/Documents/crypto/ex5/files % ./alice -f task3msg.txt

  
Here is my signature, take a loot:

2f4cd7eeb6031f4532734b9690fb1aa888d201bfd996e2ca38dff44fc0e984b0e32310fe9fdadf4c60017e2112913cd36003b645c46d0495806dcb7e62fe8535c9a20dc27667e4b929f95ca2d9d909165ce44c72829238a61cdf82c1bb0c30cc865579189f05919c84eba533b4f31a5cc930d427ea36080bf2bcf858856dbfe869699bb96494e7d3c25f992fdf1b4dabdb74f421e4df0604e874bd37ebdf1f4342b7d628f1424f52dbb90f5cc6bf556b3b475245acea32787a27f8cd2aab45d7f5ab22e2ca0114edd4bb55625a099b0f7486d0a1c1b2ff753864a61bd23a83ce506fe79d96667ee34f332218f5a9ce5bdec89ff1686e0c3e26bdd60347edfbf5a55842ec551430a5d4bc7a05d417c3782da73e73e3b489002ca9c325d8138e8604d51fc3f871931d49880e37a3ca5f394c6219092ba84408cb6d6dda6d30953cef6f19d035c5b2c762ebca85c283960a2dc513304549579d3e2cd7b50901175bdfff0333fbdaeae953ab4d6ad4d68ce94dde7c73f9afe2f727baf67be787cb086cda569e951864d2febf8e96d81eed1c96286bb103b16b1ec580980e4265c20ffb0f4fd2647bd3f969bb42e21211190894fbffbd34cb84eed8acbb55b7f46ee3cf5c96da01f6a3c22af9cffb1020a25c4dd8c2077f2d5cbd69327e27c5861a08d9fe93899c268b857390c5ce3497cc2ad9d15d9f54f070d946ff79dcaac4182
```

The code I used to sign the positive message. Unfortunately I couldn't figure out the solution. 

```py
import base64

def load_public_key(filename):
    with open(filename, 'r') as f:
        key_data = f.read().strip().split('\n')
        modulus_line = key_data[1]
        exponent_line = key_data[2]
        modulus = int.from_bytes(base64.b64decode(modulus_line.encode()), byteorder='big')
        exponent = int.from_bytes(base64.b64decode(exponent_line.encode()), byteorder='big')        
        return modulus, exponent

def decrypt_signature(signature, modulus, exponent):
    signature_int = int(signature, 16)
    decrypted_int = pow(signature_int, exponent, modulus)
    return decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, byteorder='big')

def forge_signature(message, modulus, exponent):
    forged_message = b'_p Mallory is a good student.'
    forged_message_int = int.from_bytes(forged_message, byteorder='big')
    forged_signature_int = pow(forged_message_int, exponent, modulus)
    forged_signature_hex = hex(forged_signature_int)[2:]
    return forged_signature_hex

def generate_public_key(signature, modulus, exponent):
    forged_signature_int = int(signature, 16)
    forged_message_int = pow(forged_signature_int, 1, modulus)
    forged_modulus_hex = hex(modulus)[2:]
    forged_exponent_hex = hex(exponent)[2:]
    forged_public_key = forged_modulus_hex + forged_exponent_hex
    return forged_public_key

# def verify_signature(forged_signature, original_signed_message, modulus, exponent):
#     decrypted_signature = decrypt_signature(original_signed_message, modulus, exponent)
#     return forged_signature == decrypted_signature.hex()

def main():
    modulus, exponent = load_public_key('alice.pub')
    original_signed_message = "2f4cd7eeb6031f4532734b9690fb1aa888d201bfd996e2ca38dff44fc0e984b0e32310fe9fdadf4c60017e2112913cd36003b645c46d0495806dcb7e62fe8535c9a20dc27667e4b929f95ca2d9d909165ce44c72829238a61cdf82c1bb0c30cc865579189f05919c84eba533b4f31a5cc930d427ea36080bf2bcf858856dbfe869699bb96494e7d3c25f992fdf1b4dabdb74f421e4df0604e874bd37ebdf1f4342b7d628f1424f52dbb90f5cc6bf556b3b475245acea32787a27f8cd2aab45d7f5ab22e2ca0114edd4bb55625a099b0f7486d0a1c1b2ff753864a61bd23a83ce506fe79d96667ee34f332218f5a9ce5bdec89ff1686e0c3e26bdd60347edfbf5a55842ec551430a5d4bc7a05d417c3782da73e73e3b489002ca9c325d8138e8604d51fc3f871931d49880e37a3ca5f394c6219092ba84408cb6d6dda6d30953cef6f19d035c5b2c762ebca85c283960a2dc513304549579d3e2cd7b50901175bdfff0333fbdaeae953ab4d6ad4d68ce94dde7c73f9afe2f727baf67be787cb086cda569e951864d2febf8e96d81eed1c96286bb103b16b1ec580980e4265c20ffb0f4fd2647bd3f969bb42e21211190894fbffbd34cb84eed8acbb55b7f46ee3cf5c96da01f6a3c22af9cffb1020a25c4dd8c2077f2d5cbd69327e27c5861a08d9fe93899c268b857390c5ce3497cc2ad9d15d9f54f070d946ff79dcaac4182"

    forged_signature = forge_signature(original_signed_message, modulus, exponent)
    forged_public_key = generate_public_key(forged_signature, modulus, exponent)
    # print("Forged Public Key:", forged_public_key)
    # is_valid = verify_signature(forged_signature, original_signed_message, modulus, exponent)
    # if is_valid:
    #     print("The forged signature is valid.")
    # else:
    #     print("The forged signature is invalid.")
    print("Forged Signature:", forged_signature)

if __name__ == "__main__":
    main()

```

Output:
![Forged message](images/image5.png)



