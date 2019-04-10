import hashlib
def md5(str):
    m = hashlib.md5()  # 声明一个md5对象
    m.update(str.encode('utf-8','ignore'))
    return m.hexdigest()


ha1 = md5("115:ltsip.cn:123456")  #1   response="277c78bfb96d7deb0846f73cc28e42c3"
# ha1 = md5("Mufasa:testrealm@host.com:Circle Of Life")#2
print(ha1)
ha2 = md5("REGISTER:sip:11.0.0.3;transport=UDP")  #注意;transport=UDP也是uri的内容
# ha2 = md5("GET:/dir/index.html")#2
print(ha2)
nonce ="02fbfa80e68e9c1bc189975eaeadc6cb"
# nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093"#2

cnonce = "d20ad7febce41cc979e00a1663667608"
# cnonce="0a4f113b"#2
nc = '00000001'  # 注意为固定8字节，表示请求认证的次数，不加引号
qop = 'auth'
res = md5(ha1 + ":{}:{}:{}:{}:".format(nonce, nc, cnonce, qop) + ha2)
print(res)