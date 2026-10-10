import socket
import ssl
import hashlib
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes

def encrypt_message(cipher, message):
    return cipher.encrypt(message.encode())

def decrypt_message(decipher, ciphertext):
    return decipher.decrypt(ciphertext).decode()
def creatfile(filename):
    with open(filename,'w') as f:
         x=input("type the sentence you want to hashing:")
         w=f.write(x)
def hash_file(c,filename):
    with open(filename, "rb") as f:
        data = f.read()
        h = hashlib.sha256(data).hexdigest()
        return h

def handle_server(c,decipher,cipher, secure=False):
    while True:
        try:
            z = c.recv(1204)
            if not z:
                    break
            m = decrypt_message(decipher, z)
            print("server says:", m)

            x = input("Enter msg to server: ")
            if x.lower() == "exit":
                break
            else:
                if secure:
                    ct = encrypt_message(cipher, x)
                    c.send(ct)
                else:
                    c.send(x.encode())
        except Exception as e:
            print(f"Error: {e}")
            break

def plain(soc):
    while True:
        r = soc.recv(1024)
        if not r:
          break
        print("server says:", r.decode())
        x = input("Enter msg to server: ")
        if x.lower() == "exit":
            break
        else:
            soc.send(x.encode())

h = "localhost"
port = 7777
port_i=6677

try:
   secure_mode = input("Use secure mode? (yes/no): ").strip().lower() 
   if secure_mode=="yes":
      context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
      context.load_verify_locations("server.crt")
      soc = socket.socket()
      c = context.wrap_socket(soc, server_hostname=h)
      c.connect((h, port))
      print ("connected to server")

      block_size = AES.block_size
      key_s = get_random_bytes(32)
      nonce_s = get_random_bytes(block_size // 2)
      key = c.recv(32)
      nonce = c.recv(16)
      counter = Counter.new(64, prefix=nonce_s, initial_value=0)
      counter_d = Counter.new(64, prefix=nonce, initial_value=0)

      decipher = AES.new(key, mode=AES.MODE_CTR, counter=counter_d)
      cipher = AES.new(key_s, mode=AES.MODE_CTR, counter=counter)

      print("Connected to server")
      c.send(key_s)
      c.send(nonce_s)
      m = c.recv(1024)
      msg = decipher.decrypt(m)
      print("server says:", msg.decode())
      while True:
        file_choice = input("Choose an option: 1) hash file, 2)talk to each other : ").strip()
        c.send(file_choice.encode())
        if file_choice == '1':
           z= c.recv(1024)
           p = hash_file(c,z)
           print("Hash:", p)
           x=input("enter filename:")
           creatfile(x)
           c.send(x.encode())
           h = hash_file(c,x)
           print("Hash:", h)
           break
        elif file_choice == '2':
            handle_server(c,decipher,cipher, secure=(file_choice == '2'))
            break
        elif file_choice  == 'exit':
            break
        else:
            print('Invalid file choice')
        c.close()
   elif secure_mode=="no":
           while True:
                c = socket.socket()
                c.connect((h, port_i))
                file_choice = input("Choose an option: 1) hash file, 2)talk to each other : ").strip()
                c.send(file_choice.encode())
                if file_choice == '1':
                   z= c.recv(1024)
                   p = hash_file(c,z)
                   print("Hash:", p)
                   x=input("enter filename:")
                   creatfile(x)
                   c.send(x.encode())
                   h = hash_file(cc,x)
                   print("Hash:", h)
                   break
                elif file_choice == '2':
                    plain(c)
                    break
                elif file_choice  == 'exit':
                     break
                else:
                   print('Invalid file choice')
except Exception as e:
    print(f"Error: {e}")
finally:
    c.close()