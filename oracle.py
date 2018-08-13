#!/usr/bin/env python3
import argparse, sys
from os import urandom
from functools import reduce
from base64 import b64decode, b64encode
import socket
host, port = "10.10.10.89", 9191

def sock(remoteip, remoteport):
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((remoteip, remoteport))
  return s, s.makefile('rw')

def read_until(f, delim='\n'):
  data = ''
  while not data.endswith(delim):
    data += f.read(1)
  return data

def test_validity(up_cipher):
    s, f = sock(host, port)
    read_until(f, "Insert ciphertext: ")
    s.send(b64encode(up_cipher)+b'\n')
    data = read_until(f)
    s.close
    if "Hash is OK!" in data:
      return True
    else:
      return False

def main():
    s, f = sock(host, port)
    read_until(f, 'Crack this one: ')
    cipher_text = read_until(f)
    print (cipher_text)
    s.close
    mess = b64decode(cipher_text)

    blocks = [decrypt_block(mess[i:i+16]) for i in range(0, mess.__len__(), 16)]
    preceding_ct = [b"\x00" * 16] + [mess[i:i+16] for i in range(0, mess.__len__() - 16, 16)]
    text = reduce(lambda x, y: x+y, [xor(x[0], x[1]) for x in zip(blocks, preceding_ct)], b'')
    print(text)
    print(b64encode(text))

# Technical

def xor(a, b):
    return bytearray([x[0] ^ x[1] for x in zip(a, b)])

def inc(a):
    bs = [b for b in a]
    i = bs.__len__()
    while i:
        i -= 1
        bs[i] = (bs[i] + 1) % 256
        if bs[i]:
            break
    return bytearray(bs)


def tweak(a, n):
    bs = [b for b in a]
    bs[n] = (bs[n] + 1) % 256
    return bytearray(bs)


def decrypt_block(block):
    random = bytearray(urandom(16))
    i = b'\x00' * 16
    test = xor(random, i)

    while test_validity(test + block) is False:
        i = inc(i)
        test = xor(random, i)

    j = 1
    tweaked = tweak(test[:], j-1)

    while test_validity(tweaked + block) is True:
        j += 1
        tweaked = tweak(tweaked, j-1)
        print(tweaked)

    l = 17 - j
    known = bytearray([b ^ l for b in test[-l:]])[::-1]
    while l != 16:
        random = bytearray(urandom(16 - l))
        i = b'\x00' * (16 - l)
        pad = xor(bytearray([l + 1]) * l, known)

        head = xor(random, i)

        while test_validity(head + pad + block) is False:
            print(head+pad+block)
            i = inc(i)
            head = xor(random, i)

        known = bytearray([head[-1] ^ (l+1)]) + known
        l += 1
    print(known)
    return known


if __name__ == '__main__':
    main()
