from hashlib import sha256

# 定义椭圆曲线参数 SECP256k1
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a = 0x0000000000000000000000000000000000000000000000000000000000000000
b = 0x0000000000000000000000000000000000000000000000000000000000000007
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


# 定义有限域的运算（加法和乘法）
def inv_mod_p(x):
    return pow(x, -1, p)


def add_mod_p(x, y):
    return (x + y) % p


def sub_mod_p(x, y):
    return (x - y) % p


def mul_mod_p(x, y):
    return (x * y) % p


# 定义点的运算（加法和乘法）
def add_points(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if p1 == p2:
        lam = mul_mod_p(mul_mod_p(3, x1), mul_mod_p(x1, x1))
        lam = mul_mod_p(lam, inv_mod_p(mul_mod_p(2, y1)))
    else:
        lam = mul_mod_p(sub_mod_p(y2, y1), inv_mod_p(sub_mod_p(x2, x1)))

    x3 = sub_mod_p(sub_mod_p(mul_mod_p(lam, lam), x1), x2)
    y3 = sub_mod_p(mul_mod_p(lam, sub_mod_p(x1, x3)), y1)

    return (x3, y3)


def mul_point(k, P):
    if k == 0 or P is None:
        return None
    if k == 1:
        return P

    Q = None
    R = P

    while k > 0:
        if k % 2 == 1:
            Q = add_points(Q, R)

        R = add_points(R, R)
        k = k // 2

    return Q


# 定义Schnorr Batch签名验证
def schnorr_batch_verify(messages, pubkeys, agg_sig):
    assert len(messages) == len(pubkeys) == len(agg_sig)

    for i in range(len(messages)):
        message = messages[i].encode()

        # 确定消息的哈希
        h = int.from_bytes(sha256(message).digest(), byteorder='big')

        # 分解大公钥
        x = int.from_bytes(pubkeys[i][:32], byteorder='big')
        y = int.from_bytes(pubkeys[i][32:], byteorder='big')
        P = (x, y)

        # 分解大签名
        r = int.from_bytes(agg_sig[i][:32], byteorder='big')
        s = int.from_bytes(agg_sig[i][32:], byteorder='big')

        # 验证签名
        e = h
        R = add_points(mul_point(s, P), mul_point(e, (Gx, Gy)))
        if R is None:
            return False

        if R[0] == r:
            return True
        else:
            return False


# 示例代码
if __name__ == '__main__':
    # 假设有3个签名需要验证
    messages = ["message1", "message2", "message3"]
    pubkeys = [
        b'\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef',
        b'\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef',
        b'\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef']

    # 假设有3个大签名需要验证（合并签名为一个大签名）
    agg_sig = [
        b'\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef',
        b'\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef',
        b'\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef']

    # 验证大签名
    is_valid = schnorr_batch_verify(messages, pubkeys, agg_sig)

    print("Signature is valid:", is_valid)
