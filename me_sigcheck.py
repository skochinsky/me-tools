# Intel ME partition signature checker
# Copyright (c) 2016 Igor Skochinsky
# Version 0.1 2016-11-05
#
# This software is provided 'as-is', without any express or implied
# warranty. In no event will the authors be held liable for any damages
# arising from the use of this software.
#
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely, subject to the following restrictions:
#
#    1. The origin of this software must not be misrepresented; you must not
#    claim that you wrote the original software. If you use this software
#    in a product, an acknowledgment in the product documentation would be
#    appreciated but is not required.
#
#    2. Altered source versions must be plainly marked as such, and must not be
#    misrepresented as being the original software.
#
#    3. This notice may not be removed or altered from any source
#    distribution.

import struct, hashlib, sys

def bytes2int(s, swap=True):
  num = 0
  if swap: s = s[::-1]
  for c in s:
    num = num*256 + ord(c)
  return num

if __name__ == '__main__':
    print "Intel ME partition manifest signature checker v0.1"
    if len(sys.argv) < 2:
        print "Usage: me_sigcheck.py FTPR_part.bin"
        sys.exit(1)

f = open(sys.argv[1], "rb")
hdr1 = f.read(0x80)
if hdr1[0x1C:0x20]!= '$MN2':
    print "ME manifest not found! (bad file format?)" 
    sys.exit(2)

pubkey = bytes2int(f.read(0x100))
pubexp = bytes2int(f.read(0x4))
rsasig = bytes2int(f.read(0x100))

print "public key:", hex(pubkey)
print "exponent:", hex(pubexp)
print "signature", hex(rsasig)

decsig = pow(rsasig, pubexp, pubkey)

sigstr = hex(decsig)
print "decrypted signature:", sigstr

# header length
hlen = struct.unpack("<I", hdr1[4:8])[0] * 4
# manifest length
mlen = struct.unpack("<I", hdr1[0x18:0x1C])[0] * 4

# read trailer of the manifest
f.seek(hlen)
hdr2 = f.read(mlen-hlen)

h = hashlib.sha256()
h.update(hdr1)
h.update(hdr2)
hashstr = hex(bytes2int(h.digest(), False))
print "manifest hash:", hashstr
# TODO: check 0x1ff.... at the start of signature
if sigstr.endswith(hashstr[2:]):
   print "signature seems valid"
else:
   print "signature is INVALID!"
   sys.exit(3)

