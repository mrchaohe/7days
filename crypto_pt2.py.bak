from OpenSSL import crypto
# 利用私钥签名很简单：
# 读取私钥
private_key_file = '/home/wangtao/private_key.pem'
with open(private_key_file, 'rb') as pkey_file:
    private_key_content = pkey_file.read()
if isinstance(private_key_content, bytes):
    private_key_content = private_key_content.decode('utf-8')

# 将字符串签名：
content = 'xxoo'
pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key_content)
signature = crypto.sign(pkey, content, 'md5')

# 公钥验证签名：
his_sign = ''       # 密钥
verify_str = ''     # 等待验证的内容
cpay_public_key = '/home/wangtao/public_key.pem'
pub_key = crypto.load_publickey(crypto.FILETYPE_PEM, cpay_public_key)
x509 = crypto.X509()
x509.set_pubkey(pub_key)
try:
    crypto.verify(x509, his_sign, verify_str, 'md5')
except crypto.Error:
    print('验证不通过')
    exit()
print('验证通过~~')
