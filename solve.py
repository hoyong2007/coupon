import os
from sage.all import *
from Crypto.Util.number import long_to_bytes as l2b
from Crypto.Util.number import bytes_to_long as b2l
from pwn import *

#r = process('./coupon')
r = remote('0', 5559)
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
f3 = T1_p + (C3_p[0]-C1_p[0])*X**4 + (C3_p[1]-C1_p[1])*X**3 + (C3_p[2]-C1_p[2])*X**2

coupon = hex(C3).replace('0x','').replace('L','')
if len(coupon) & 1:
    coupon = '0' + coupon

for H,_ in poly.roots():
    tag = hex(poly_to_int(f3(H))).replace('0x','').replace('L','')
    if len(tag) & 1:
        tag = '0' + tag
    try_verify(coupon, tag)


