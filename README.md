# project21-group11

Schnorr Batch是一种对Schnorr签名进行批处理的技术，它允许在一次计算中同时验证多个Schnorr签名，从而提高了验证的效率。Schnorr签名是一种基于离散对数问题的数字签名方案，被认为比传统的ECDSA（Elliptic Curve Digital Signature Algorithm）更高效和安全。

在传统的Schnorr签名验证中，对每个签名都需要单独执行一次离散对数运算，这可能会导致验证过程的性能瓶颈，尤其是在批量验证的情况下。Schnorr Batch技术通过将多个签名合并为一个更大的签名，并将验证过程转换为对该大签名进行一次离散对数运算，从而提高了验证的效率。

运行结果：<img width="560" alt="575fdc9b01ed7d487f497408d5c24b4" src="https://github.com/zsygroup11num1/project21-group11/assets/129477117/adee2f6a-ec07-4486-82b8-f58bd89cc01f">
