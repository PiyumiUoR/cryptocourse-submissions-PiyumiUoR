# Task 1

The `cryptography` library in python supports AES-GCM. The encryption of plaintext using `cryptography` can be shown as below. But when I try to use the 2 or 44 bytes it gives this error. Therefore, I am using the proposed tag length in the error message. 

```terminal
Ciphertext: 8651115fe1cf321259cd40d734778c04762d14
Tag: 98535f9a
Length: 4
Traceback (most recent call last):
  File "/home/arch/Documents/crypto/ex4/task1-en.py", line 32, in <module>
    decrypted_plaintext = decrypt_AES_GCM(key, nonce, ciphertext, tag, associated_data)
                          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/arch/Documents/crypto/ex4/task1-en.py", line 15, in decrypt_AES_GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag[:4]), backend=backend)
                                         ^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.11/site-packages/cryptography/hazmat/primitives/ciphers/modes.py", line 245, in __init__
    raise ValueError(
ValueError: Authentication tag must be 16 bytes or longer.
```

The Python code I used is as follows.

```py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets

def encrypt_AES_GCM(key, nonce, plaintext, associated_data):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag=None), backend=default_backend())
    encrypt = cipher.encryptor()
    encrypt.authenticate_additional_data(associated_data)
    ciphertext = encrypt.update(plaintext) + encrypt.finalize()
    tag = encrypt.tag
    return ciphertext, tag

def decrypt_AES_GCM(key, nonce, ciphertext, tag, associated_data):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decrypt = cipher.decryptor()
    decrypt.authenticate_additional_data(associated_data)
    plaintext = decrypt.update(ciphertext) + decrypt.finalize()
    return plaintext

key = secrets.token_bytes(16) #AES-128
nonce = secrets.token_bytes(12)  
plaintext = b'Cryptographic Systems'
associated_data = b'Their weaknesses'

ciphertext, tag = encrypt_AES_GCM(key, nonce, plaintext, associated_data)
print("Ciphertext:", ciphertext.hex())
print("Tag:", tag.hex())
print("Tag Length:", len(tag))

decrypted_plaintext = decrypt_AES_GCM(key, nonce, ciphertext, tag, associated_data)
print("Decrypted plaintext:", decrypted_plaintext.decode())

```

The output:

```terminal
Ciphertext: 079326955beb71b596f0495a9d11c9e17427297fa7
Tag: 3f0a1f75d087cc64de1764bfae23fecc
Tag Length: 16
Decrypted plaintext: Cryptographic Systems
```

I tried brute forcing and I was unable to match the whole tag length of the `ciphertext1` to another one. The VM kept getting stuck. Therefore I matched the initial 3 bytes. The script is as follows.

```py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets

def encrypt_AES_GCM(key, nonce, plaintext, associated_data):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(associated_data)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    return key, ciphertext, tag

def decrypt_AES_GCM(key, nonce, ciphertext, tag, associated_data):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(associated_data)
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext    

key = secrets.token_bytes(16)  # AES-128 key
nonce = secrets.token_bytes(12)
plaintext1 = b'Cryptographic Systems'
associated_data = b'Their weaknesses'

key_1, ciphertext1, tag_o = encrypt_AES_GCM(key, nonce, plaintext1, b'')

def try_bruteforce(key, nonce, desired_tag):
    while True:          
        plaintext = secrets.token_bytes(32)  
        key, ciphertext, tag = encrypt_AES_GCM(key, nonce, plaintext, b'')  
        if tag[:3] == desired_tag[:3]:
            return plaintext, ciphertext, key, nonce, tag

desired_tag = tag_o  

plaintext2, ciphertext2, key_2, nonce_2, tag_bf = try_bruteforce(key, nonce, desired_tag)

print("Plaintext 1:", plaintext1.hex())
print("Plaintext 2:", plaintext2.hex())
print("Ciphertext 2:", ciphertext2.hex())
print("Key 1:", key_1.hex())
print("Key 2:", key_2.hex())
print("Nonce:", nonce_2.hex())
print("Tag 1:", tag_o.hex())
print("Tag 2:", tag_bf.hex())
```

The output:

```terminal
Plaintext 1: 43727970746f677261706869632053797374656d73
Plaintext 2: 2a161c81059f0b3a2d5d7fde8293a3cee9465e665b0da67835b491913e8dd88c
Ciphertext 2: 071959cde5d0b1bf9abbc65ccc5ecc981958ef40badba0781124d3da5130e845
Key 1: d15be5c18c1e8d7b7169253e05045be0
Key 2: d15be5c18c1e8d7b7169253e05045be0
Nonce: 90228c3c900dfd0b4c8f1654
Tag 1: 8e432bbee1fbf7339e47a64a3998003a
Tag 2: 8e432b82b4267393976e30fc57719ef8
python task1-en.py  380.18s user 7.25s system 68% cpu 9:23.82 total
```

# Task 2

I tried with the below code. 

```py
import subprocess
import json
from time import time
import base64

def send_request(tag):
    hex_ciphertext = "efbfbdefbfbdefbfbdefbfbdefbfbdefbfbdefbfbdefbfbdefbfbdefbfbdefbfbdefbfbdefbfbdefbfbdefbfbdefbfbdefbfbd3e161110efbfbd0aefbfbdefbfbd2f49efbfbd1e06efbfbdefbfbd212defbfbd453eefbfbdefbfbdefbfbdefbfbd04efbfbd79efbfbdefbfbdefbfbd36efbfbdefbfbd59efbfbd5befbfbd2a4c226a65efbfbd4348efbfbd3741efbfbdefbfbd767f73efbfbd5107efbfbdefbfbd225a08efbfbdefbfbdefbfbd632befbfbdefbfbd1aefbfbdefbfbdefbfbdefbfbdefbfbd19efbfbd1d0aefbfbdefbfbdefbfbd314208efbfbd253e2f1aefbfbd032d442122efbfbddb87efbfbd0823204317efbfbd035e6defbfbd4225efbfbd132c3d51efbfbdefbfbd74efbfbdefbfbd32efbfbd0c25efbfbd3fefbfbdefbfbdd184efbfbd2708efbfbd1c2befbfbd4ac4aa25103fefbfbdefbfbd274f68657d0a010befbfbd19733c424869efbfbd34efbfbd3947efbfbd63efbfbd5defbfbd327d42efbfbddc8befbfbdefbfbdefbfbdefbfbd18efbfbd3a664cefbfbd02"
    ciphertext_bytes = bytes.fromhex(hex_ciphertext)
    ciphertext_in_base64 = base64.b64encode(ciphertext_bytes).decode('utf-8')
    data = {
        "sender": "Bob",
        "receiver": "Alice",
        "data": ciphertext_in_base64,
        "tag": tag
    }
    json_data = json.dumps(data).encode('utf-8')
    start_time = time()
    response = subprocess.run(["./authenticator", "-f", "./input.json", "-j"], input=json_data, capture_output=True)
    end_time = time()
    return end_time - start_time

def determine_tag_length():
    tag_length = 1
    while True:
        time_diff1 = send_request("00" * tag_length)
        time_diff2 = send_request("FF" * tag_length)
        if abs(time_diff1 - time_diff2) > 0.05:  
            return tag_length
        tag_length += 1

def timing_attack():
    tag_length = determine_tag_length()
    target_tag = "00" * tag_length    
    for i in range(tag_length):
        max_time = 0
        max_byte = None        
        for byte in range(256):
            modified_tag = target_tag[:i] + format(byte, '02x') + target_tag[i+2:]
            time_diff = send_request(modified_tag)
            if time_diff > max_time:
                max_time = time_diff
                max_byte = byte
                final_modified_tag = modified_tag

    print("Finally Modified Tag:", final_modified_tag)
timing_attack()

```

# Task 3

The code:

```py
mod = 2**128
H = 0x92178D4026DA1DCA4296778730EB9A9E

def ghash(H, m):
    result = 0
    for byte in m:
        result = (result * 256 + byte) % mod
        result = (result * H) % mod
    return result

def find_short_cycle(H):
    visited = set()
    cycle_length = 0
    current_H = H

    while True:
        if current_H in visited:
            break
        visited.add(current_H)
        current_H = (current_H * H) % mod
        cycle_length += 1
    return current_H, cycle_length

cycle_value, cycle_length = find_short_cycle(H)
print("Value of a cycle:", hex(cycle_value))
print("Cycle length:", cycle_length)

message_block = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xee'
ghash_ori = ghash(H, message_block)
print("Original message:", hex(ghash_ori))
message_block_re = b'\x00\x00\x00\x00\xee\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
ghash_re = ghash(H, message_block_re)
print("Rearranged message:", hex(ghash_re))

```

The output:

```terminal
Value of a cycle: 0x0
Cycle length: 128
Original message: 0xd1e551a41ec7b209e7e31faf7b09bee4
Rearranged message: 0xde786e0000000000000000000000000
```

# Task 4

The code:

```py
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

key = get_random_bytes(16)  # Random 128-bit key
iv = get_random_bytes(16)   # Random IV

def cbc_mac(message):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    mac = cipher.encrypt(pad(message, AES.block_size))[-AES.block_size:]
    return mac

# client
def generate_message():
    message = "from=alice;to=bob;amount=40;"
    mac = cbc_mac(message.encode())
    return message, iv, mac

# CServer
def receive_and_validate(message, received_iv, received_mac):
    computed_mac = cbc_mac(message.encode())
    if computed_mac == received_mac:
        print("Message is authentic.")
    else:
        print("Tampered message.")

# man-in-the-middle
def forge_message(original_message, received_iv, received_mac):
    modified_message = original_message.replace("40", "400")  # Increase the amount
    return modified_message, received_iv, received_mac

original_message, original_iv, original_mac = generate_message()
print("Original Message:", original_message)
print("Original IV:", original_iv)
print("Original MAC:", original_mac.hex())

# Attacker intercepts and modifies the message
modified_message, modified_iv, modified_mac = forge_message(original_message, original_iv, original_mac)

# Consumer receives and validates the modified message

receive_and_validate(modified_message, modified_iv, modified_mac)
print("\nModified message:", modified_message)

```

```terminal
Original Message: from=alice;to=bob;amount=40;
Original IV: b'\xad\xac\x07M&\x97?\xe7\x15\x99\x0e\r]\xa5}\xc8'
Original MAC: dc871b1e14ff0b87b8de7e070740ce50
Tampered message.

Modified message: from=alice;to=bob;amount=400;
```

