from OpenSSL import crypto

_k = crypto.PKey()
_cert = crypto.X509()

# Create keys
_k.generate_key(crypto.TYPE_RSA, 2048)

# Add argument for create certificate
_cert.gmtime_adj_notBefore(0)
_cert.gmtime_adj_notAfter(0*365*24*60*60) #10 years expiry date
_cert.set_pubkey(_k)
_cert.sign(_k, 'sha256')

# Create key's file
with open("public_key.pem",'w') as f:
    f.write(crypto.dump_publickey(crypto.FILETYPE_PEM, _k))

with open("private_key.pem",'w') as f:
    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, _k))

with open("certificate.pem",'w') as f:
    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, _cert))

#-------------------------------------------------------------------------------

# Open key and load in var
with open("private_key.pem",'r') as f:
    priv_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

with open("public_key.pem",'r') as f:
    pub_key = crypto.load_publickey(crypto.FILETYPE_PEM, f.read())

with open("certificate.pem",'r') as f:
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

# sign message 'hello world' with private key and certificate
sign = crypto.sign(priv_key, "hello world", 'sha256')
print crypto.verify(cert, sign, "hello world", 'sha256')




from OpenSSL.crypto import load_publickey, FILETYPE_PEM, verify, X509
# ... code ...
x509 = X509()
x509.set_pubkey(pub_key)
# ... code ...
print verify(x509, sign, sha, 'sha256')