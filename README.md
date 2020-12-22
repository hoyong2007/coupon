# coupon

### 출제 의도

크립토 구현물에서 발생하는 취약점은 표준에 나와있는 규정을 잘 지키지 않아서 발생하기도 한다. 대표적으로 Initial Vector의 경우 rfc4106(The Use of Galois/Counter Mode (GCM) in IPsec Encapsulating Security Payload (ESP)) 문서처럼 **'For a given key, the IV MUST NOT repeat.'** 라고 명시해 놓지만, 개발자들이 이를 모르고 iv값을 고정하는 등의 실수를 저질러 취약점이 발생하기도 한다. 이처럼 알려진지는 오래되었지만 최근에도 종종 찾아볼 수 있는 실수인 iv reuse의 위험성에 대해 다뤄보고자 하였다.

### 취약점 설명

핵심 취약점은 init() 함수부분에 있다.

![img](.\README.assets\Untitled-1608120289794.png) 

쿠폰을 암호화 할때 AES-GCM을 사용하는데, 이때 init() 함수에서 iv 값인 a1+545 부분을 get_rand_bytes() 함수를 통해 랜덤 값으로 초기화 하는데, init() 이후에는 iv값이 변경되지 않아 두 개의 쿠폰을 발급받게 되면 같은 iv값을 사용해 암호화를 하게 된다. 

기본적으로 쿠폰을 발급받을 때 품목이 flag인 쿠폰은 발급받을 수 없지만 iv reuse로 인해 선물 품목이 flag인 쿠폰과 해당 쿠폰의 tag값을 생성할 수 있다.

### 풀이

![img](.\README.assets\Untitled.png) 

aes-gcm모드의 구조를 보면 iv 값과 key 값이 같다면 암호화에 사용하는 key stream이 같게 된다. 

이때 생성되는 key stream과 plaintext를 단순히 xor 함으로써 암호화를 진행하기 때문에 암호문-평문쌍을 알고있다면 해당 key stream을 이용해 원하는 평문을 암호화한 암호문을 구할 수 있다.

![1608120177023](.\README.assets\1608120177023.png)

이를 이용해 쿠폰의 present 부분이 flag인 쿠폰을 생성할 수 있다. 그러나 쿠폰을 사용하려면 생성된 쿠폰에 대한 valid한 tag 값이 필요하다.

Auth Tag는 평문 블럭이 N개일때 다음과 같이 해시키 **H**에 대한 다항식으로 표현할 수 있다.

![1608120206250](.\README.assets\1608120206250.png)

임의의 암호문을 만들었을 때 valid한 tag값 **T**를 계산하려면 $E_k$와 **H**를 알아야 한다. 

이때, 같은 iv값을 사용해 같은 $E_k$ 값을 갖는 두 개의 **(C,T)** 쌍을 갖고 있다면 아래와 같이  $E_k$를 제거할 수 있다.

![1608120224315](.\README.assets\1608120224315.png)

이렇게 얻어진 **H**에 대한 N+2차 다항식의 해를 구하면 해시키를 구할 수 있다.

해시키 H 값을 구했으면 아래와 같이 임의의 암호문에 대한 valid한 tag값을 계산할 수 있다.

![1608120354259](.\README.assets\1608120354259.png)

위 연산은 $GF(2^{128})$ 위에서 이루어진다는 것에 유의해야 한다.

이렇게 present 부분이 flag인 쿠폰과 이 쿠폰의 tag값을 생성했으면 이를 제출해 flag를 읽을 수 있다.

![img](.\README.assets\Untitled-1608120384634.png) 

### 풀이 코드

```python
# solve.py
import os
from sage.all import *
from Crypto.Util.number import long_to_bytes as l2b
from Crypto.Util.number import bytes_to_long as b2l
from pwn import *

r = process('./coupon')
sleep(1)

def get_coupon(name, gift):
    r.recvuntil('4. exit\n')
    r.sendline('2')
    r.recvuntil(' : ')
    r.send(name)
    r.recvuntil(' : ')
    r.send(gift)
    r.recvuntil('Coupon : ')
    C = int(r.recvuntil('\n')[:-1],16)
    r.recvuntil('Tag : ')
    T = int(r.recvuntil('\n')[:-1],16)
    return C, T

def try_verify(C,T):
    r.recv()
    r.sendline('3')
    r.recv()
    r.sendline(C)
    r.recv()
    r.sendline(T)
    r.recvuntil('===========================\n')
    print r.recvuntil('\n')

def pad(msg):
    ret = msg
    if len(msg) % 16 != 0:
        ret += '\0' * ((16 - len(msg))%16)
    return ret

F = GF(2**128, names='a')
(a,) = F._first_ngens(1)
R = PolynomialRing(F, names='X')
(X,) = R._first_ngens(1)

def block_to_poly(block):
    global F
    f = 0
    for e, bit in enumerate(bin(block).replace('0b','').rjust(128,'0')):
        f += int(bit) * a**e
    return f

def poly_to_int(poly):
    a = 0
    for i, bit in enumerate(poly._vector_()):
        a |= int(bit) << (127 - i)
    return a

def make_bytes_to_poly(msg):
    pad_cnt = (16 - len(msg))%16
    msg += '\x00' * pad_cnt
    return [block_to_poly(b2l(msg[i*16:(i+1)*16])) for i in range(len(msg)/16)]

C1, T1 = get_coupon('john', 'unicorn')
C2, T2 = get_coupon('john', 'house')
A = b2l('coupon center v1')
M1 = b2l(pad(("Santa's coupon for %s :)\nPresent: %s") % ('john','unicorn')))
M2 = b2l(pad(("Santa's coupon for %s :)\nPresent: %s") % ('john','house')))
M3 = b2l(pad(("Santa's coupon for %s :)\nPresent: %s") % ('john','flag')))
C3 = C1 ^ M1 ^ M3

C1_p = make_bytes_to_poly(l2b(C1))
C2_p = make_bytes_to_poly(l2b(C2))
C3_p = make_bytes_to_poly(l2b(C3))

A_p = make_bytes_to_poly(l2b(A))[0]
T1_p = make_bytes_to_poly(l2b(T1))[0]
T2_p = make_bytes_to_poly(l2b(T2))[0]

poly = (C1_p[0]-C2_p[0])*X**4 + (C1_p[1]-C2_p[1])*X**3 + (C1_p[2]-C2_p[2])*X**2 + (T1_p-T2_p)
t3 = T1_p + (C3_p[0]-C1_p[0])*X**4 + (C3_p[1]-C1_p[1])*X**3 + (C3_p[2]-C1_p[2])*X**2

coupon = hex(C3).replace('0x','').replace('L','')
if len(coupon) & 1:
    coupon = '0' + coupon

for H,_ in poly.roots():
    tag = hex(poly_to_int(t3(H))).replace('0x','').replace('L','')
    if len(tag) & 1:
        tag = '0' + tag
    try_verify(coupon, tag)
```

```python
$ sage -python solve.py
```

# Ref

[https://tools.ietf.org/html/rfc4106#section-3.1](https://tools.ietf.org/html/rfc4106#section-3.1)

[https://en.wikipedia.org/wiki/Galois/Counter_Mode](https://en.wikipedia.org/wiki/Galois/Counter_Mode)

[https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/comments/800-38-series-drafts/gcm/joux_comments.pdf](https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/comments/800-38-series-drafts/gcm/joux_comments.pdf)

