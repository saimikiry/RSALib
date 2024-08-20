import sympy
from RSALib import RSA
from Crypto.Random import get_random_bytes

def createRSAKey(e):
    result = dict()
    result['e'] = e

    while 1:
        p = sympy.randprime(2**1023, 2**1024)
        q = sympy.randprime(2**1023, 2**1024)

        fi_n = (p-1) * (q-1)

        if p != q and (fi_n % e) != 0:
            break

    result['n'] = p * q

    result['d'] = pow(e, -1, fi_n)
    
    return result

aes_key = get_random_bytes(32)

print(f'AES key {int.from_bytes(aes_key, "big")}')

encrypter = RSA()
path_file = 'file/bin'

rsa_key = createRSAKey(3)

print('Generated key: {')
print('\tn : ' + str(rsa_key['n']))
print('\te : ' + str(rsa_key['e']))
print('\td : ' + str(rsa_key['d']) + '\n}')

encrypter.encrypt(path_file, aes_key, rsa_key)
encrypter.decrypt(path_file + '.eRSA', rsa_key['d'])

encrypter.create_signature(path_file + '.eRSA', rsa_key['e'], rsa_key['d'], rsa_key['n'])
encrypter.check_signature(path_file + '.eRSA.sRSA', path_file +'.eRSA')
