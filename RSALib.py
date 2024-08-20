import time
import asn1
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Cryptodome.Hash import SHA256
from termcolor import colored

def asn_crypt(msg, key, e, n):
    encoder = asn1.Encoder()
    encoder.start()
    encoder.enter(asn1.Numbers.Sequence)
    encoder.enter(asn1.Numbers.Set)  # RSA Keys
    encoder.enter(asn1.Numbers.Sequence)  # First key
    encoder.write(b'\x00\x01', asn1.Numbers.OctetString)  # RSA algorithm ID
    encoder.write(b'\x0C\x00', asn1.Numbers.UTF8String)  # Key ID (empty)
    encoder.enter(asn1.Numbers.Sequence)  # First key value
    encoder.write(n, asn1.Numbers.Integer) # n
    encoder.write(e, asn1.Numbers.Integer) # e
    encoder.leave()
    encoder.enter(asn1.Numbers.Sequence) # Params (empty for RSA)
    encoder.leave()
    encoder.enter(asn1.Numbers.Sequence)  # RSA data
    encoder.write(key, asn1.Numbers.Integer) # data (AES key)
    encoder.leave()  # leave from RSA data
    encoder.leave()  # leave from RSA first key
    encoder.leave()  # leave from RSA keys
    encoder.enter(asn1.Numbers.Sequence)  # Additional data
    encoder.write(b'\x10\x82', asn1.Numbers.OctetString)  # AES(CBC) algorithm ID
    encoder.write(len(msg), asn1.Numbers.Integer)  # data length
    encoder.leave()
    encoder.leave()
    encoder.write(msg)  # main data
    return encoder.output()  # exit
    
def asn_decrypt(msg):
    decoder = asn1.Decoder()
    decoder.start(msg)
    decoder.enter()
    decoder.enter()
    decoder.enter()
    value = decoder.read()  # RSA ID
    value = decoder.read()
    decoder.enter()
    n = decoder.read()[1]  # RSA key data = n, e
    e = decoder.read()[1]
    decoder.leave()
    decoder.enter()  # RSA params (empty)
    decoder.leave()
    decoder.enter()
    aes_key = decoder.read()[1]  # RSA data (AES key)
    decoder.leave()
    decoder.leave()
    decoder.leave()
    decoder.enter()
    value = decoder.read()[1]  # AES-CBC id
    if not value == (b'\x10\x82'):
        print("Incorrect symmetric algorithm!")
    length = decoder.read()[1]  # data length
    decoder.leave()
    decoder.leave()
    data = decoder.read()[1]  # main data
    return data, aes_key, n

def asn_sign_create(s, e, n):
    encoder = asn1.Encoder()
    encoder.start()
    encoder.enter(asn1.Numbers.Sequence) # Header
    encoder.enter(asn1.Numbers.Set)  # RSA-SHA256 keys
    encoder.enter(asn1.Numbers.Sequence)  # ключ и подпись
    encoder.write(b'\x00\x40', asn1.Numbers.OctetString)  # RSA-SHA256 ID
    encoder.write(b'\x0C\x00', asn1.Numbers.UTF8String)  # key ID (empty)
    encoder.enter(asn1.Numbers.Sequence) # First key value
    encoder.write(n, asn1.Numbers.Integer)  # n
    encoder.write(e, asn1.Numbers.Integer)  # e
    encoder.leave()
    encoder.enter(asn1.Numbers.Sequence) # Params (empty)
    encoder.leave()
    encoder.enter(asn1.Numbers.Sequence) # message sign
    encoder.write(s, asn1.Numbers.Integer)  # s
    encoder.leave()
    encoder.leave()
    encoder.leave()
    encoder.enter(asn1.Numbers.Sequence)  # additional data (empty)
    encoder.leave()
    encoder.leave()
    return encoder.output()

def asn_sign_check(data):
    decoder = asn1.Decoder()
    decoder.start(data)
    decoder.enter()
    decoder.enter()
    decoder.enter()
    value = decoder.read()  # RSA-SHA256 ID
    value = decoder.read()  # key ID (empty)
    decoder.enter()
    n = decoder.read()[1] # n
    e = decoder.read()[1] # e
    decoder.leave()
    decoder.enter() # Params (empty)
    decoder.leave()
    decoder.enter()
    s = decoder.read()[1] # sign
    decoder.leave()
    decoder.leave()
    decoder.leave()
    decoder.enter()  # additional data (empty)
    decoder.leave()
    decoder.leave()
    return s, e, n

class RSA:

    def __init__(self):
        iv = 0

    def executeWithTimer(self, preExecText, func, func_argv):
        print(preExecText, end=' ')
        start_time = time.time() * 1000
        result = func(*func_argv)
        end_time = time.time() * 1000
        print("OK (" + str(end_time - start_time) + str("ms)"))
        return result


    def encrypt(self, path_file, aes_key, rsa_key):
        print(colored('[RSA]', 'blue', attrs=['bold']), colored('Starting encryption ', 'white') + colored(str(path_file), 'green'))
        start_time = time.time() * 1000

        file = self.executeWithTimer(
            " > Reading file ...",
            open(path_file, 'rb').read,
            []
        )

        aes_cipher = AES.new(aes_key, AES.MODE_CBC)
        aes_ciphertext = aes_cipher.encrypt(pad(file, AES.block_size))
        self.iv = aes_cipher.iv

        rsa_ciphertext = self.executeWithTimer(
            " > RSA encrypting ...",
            pow,
            [int.from_bytes(aes_key, "big"), rsa_key['e'], rsa_key['n']]
        )

        out = self.executeWithTimer(
            " > Creating ASN.1 structure ...",
            asn_crypt,
            [aes_ciphertext, rsa_ciphertext, rsa_key['e'], rsa_key['n']]
        )

        self.executeWithTimer(
            " > Writing to file ...",
            open(path_file + '.eRSA', 'wb').write,
            [out]
        )

        end_time = time.time() * 1000
        print(colored('[RSA]', 'blue', attrs=['bold']), colored('Encryption completed! (', 'white') + colored(str(end_time - start_time), 'green'), colored('ms)', 'white'))
        

    def decrypt(self, path_file, d):
        print(colored('[RSA]', 'blue', attrs=['bold']), colored('Starting decryption ', 'white') + colored(str(path_file), 'green'))
        start_time = time.time() * 1000

        file = self.executeWithTimer(
            " > Reading file ...",
            open(path_file, 'rb').read,
            []
        )

        data, aes_key, n = self.executeWithTimer(
            " > Unwrapping ASN.1 structure ...",
            asn_decrypt,
            [file]
        )
        
        aes_key = self.executeWithTimer(
            " > RSA decrypting ...",
            pow,
            [aes_key, d, n]
        )

        cipher = AES.new(aes_key.to_bytes(32, byteorder = 'big'), AES.MODE_CBC, self.iv)
        ciphertext = cipher.decrypt(data)

        self.executeWithTimer(
            " > Writing to file ...",
            open(path_file + '.dRSA', 'wb').write,
            [ciphertext]
        )

        end_time = time.time() * 1000
        print(colored('[RSA]', 'blue', attrs=['bold']), colored('Decryption completed! (', 'white') + colored(str(end_time - start_time), 'green'), colored('ms)', 'white'))


    def create_signature(self, path_file, e, d, n):
        print(colored('[RSA]', 'blue', attrs=['bold']), colored('Starting signature creation ', 'white') + colored(str(path_file), 'green'))
        start_time = time.time() * 1000

        plain_text = self.executeWithTimer(
            " > Reading file ...",
            open(path_file, 'rb').read,
            []
        )

        h = SHA256.new(plain_text)
        cipher_text = h.digest()

        s = self.executeWithTimer(
            " > Creating signature ...",
            pow,
            [int.from_bytes(cipher_text, 'big'), d, n]
        )

        text = self.executeWithTimer(
            " > Creating ASN.1 structure ...",
            asn_sign_create,
            [s, e, n]
        )
        
        self.executeWithTimer(
            " > Writing to file ...",
            open(path_file + ".sRSA", 'wb').write,
            [text]
        )

        end_time = time.time() * 1000
        print(colored('[RSA]', 'blue', attrs=['bold']), colored('Signature creation completed! (', 'white') + colored(str(end_time - start_time), 'green'), colored('ms)', 'white'))

    def check_signature(self, path_file, path_data):
        print(colored('[RSA]', 'blue', attrs=['bold']), colored('Starting signature checking ', 'white') + colored(str(path_file), 'green'))
        start_time = time.time() * 1000

        data = self.executeWithTimer(
            " > Reading file ...",
            open(path_file, 'rb').read,
            []
        )

        sign, e, n = self.executeWithTimer(
            " > Unwrapping ASN.1 structure ...",
            asn_sign_check,
            [data]
        )

        sign = self.executeWithTimer(
            " > Calculating signature ...",
            pow,
            [sign, e, n]
        )

        plain_text = self.executeWithTimer(
            " > Reading encrypted file ...",
            open(path_data, 'rb').read,
            []
        )

        h = SHA256.new(plain_text)
        cipher_text = h.digest()
        sign_2 = int.from_bytes(cipher_text, 'big')

        if sign == sign_2:
            end_time = time.time() * 1000
            print(colored('[RSA]', 'blue', attrs=['bold']), colored('Signature creation completed! It\'s CORRECT (', 'white') + colored(str(end_time - start_time), 'green'), colored('ms)', 'white'))
        else:
            end_time = time.time() * 1000
            print(colored('[RSA]', 'blue', attrs=['bold']), colored('Signature creation completed! It\'s INCORRECT (', 'white') + colored(str(end_time - start_time), 'green'), colored('ms)', 'white'))
