#!/usr/bin/env python

# Intel ME ROM image dumper/extractor
# Copyright (c) 2012-2014 Igor Skochinsky
# Version 0.1 2012-10-10
# Version 0.2 2013-08-15
# Version 0.3 2014-10-06
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


import ctypes
import struct
import sys
import os
import array

uint8_t  = ctypes.c_ubyte
char     = ctypes.c_char
uint32_t = ctypes.c_uint
uint64_t = ctypes.c_uint64
uint16_t = ctypes.c_ushort

def replace_bad(value, deletechars):
    for c in deletechars:
        value = value.replace(c,'_')
    return value

def read_struct(li, struct):
    s = struct()
    slen = ctypes.sizeof(s)
    bytes = li.read(slen)
    fit = min(len(bytes), slen)
    ctypes.memmove(ctypes.addressof(s), bytes, fit)
    return s

def get_struct(str_, off, struct):
    s = struct()
    slen = ctypes.sizeof(s)
    bytes = str_[off:off+slen]
    fit = min(len(bytes), slen)
    if fit < slen:
        raise Exception("can't read struct: %d bytes available but %d required" % (fit, slen))
    ctypes.memmove(ctypes.addressof(s), bytes, fit)
    return s

def DwordAt(f, off):
    return struct.unpack("<I", f[off:off+4])[0]

def hexdump(s):
    if isinstance(s, str):
        s = map(ord, s)
    return " ".join("%02X" % v for v in s)

class MeModuleHeader1(ctypes.LittleEndianStructure):
    _fields_ = [
        ("Tag",            char*4),   # $MME
        ("Guid",           uint8_t*16), #
        ("MajorVersion",   uint16_t), #
        ("MinorVersion",   uint16_t), #
        ("HotfixVersion",  uint16_t), #
        ("BuildVersion",   uint16_t), #
        ("Name",           char*16),  #
        ("Hash",           uint8_t*20), #
        ("Size",           uint32_t), #
        ("Flags",          uint32_t), #
        ("Unk48",          uint32_t), #
        ("Unk4C",          uint32_t), #
    ]

    def __init__(self):
        self.Offset = None

    def comptype(self):
        return COMP_TYPE_NOT_COMPRESSED

    def print_flags(self):
        print "    Disable Hash:   %d" % ((self.Flags>>0)&1)
        print "    Optional:       %d" % ((self.Flags>>1)&1)
        if self.Flags >> 2:
            print "    Unknown B2_31: %d" % ((self.Flags>>2))

    def pprint(self):
        print "Header tag:     %s" % (self.Tag)
        nm = self.Name.rstrip('\0')
        print "Module name:    %s" % (nm)
        print "Guid:           %s" % (hexdump(self.Guid))
        print "Version:        %d.%d.%d.%d" % (self.MajorVersion, self.MinorVersion, self.HotfixVersion, self.BuildVersion)
        print "Hash:           %s" % (hexdump(self.Hash))
        print "Size:           0x%08X" % (self.Size)
        if self.Offset != None:
            print "(Offset):       0x%08X" % (self.Offset)
        print "Flags:          0x%08X" % (self.Flags)
        self.print_flags()
        print "Unk48:          0x%08X" % (self.Unk48)
        print "Unk4C:          0x%08X" % (self.Unk4C)

    def print_map(self):
        nm = self.Name.rstrip('\0').ljust(16, ' ')
        base = self.ModBase
        codestart = base
        codeend = base + self.CodeSize
        dataend = base + self.MemorySize
        curoff = base
        if codestart:
            if curoff < codestart:
                print "%08X %08X  %s GAP" % (curoff, codestart, nm)
                curoff = codestart
            print "%08X %08X  %s CODE" % (curoff, codeend, nm)
            curoff = codeend
        if curoff < dataend:
            print "%08X %08X  %s DATA" % (curoff, dataend, nm)
            curoff = dataend
        if curoff & 0xFFF:
            gapend = (curoff + 0xFFF) & ~0xFFF
            print "%08X %08X  %s GAP" % (curoff, gapend, nm)
            curoff = gapend

class MeModuleFileHeader1(ctypes.LittleEndianStructure):
    _fields_ = [
        ("Tag",            char*4),   # $MOD
        ("Unk04",          uint32_t), #
        ("Unk08",          uint32_t), #
        ("MajorVersion",   uint16_t), #
        ("MinorVersion",   uint16_t), #
        ("HotfixVersion",  uint16_t), #
        ("BuildVersion",   uint16_t), #
        ("Unk14",          uint32_t), #
        ("CompressedSize", uint32_t), #
        ("UncompressedSize", uint32_t), #
        ("LoadAddress",    uint32_t), #
        ("MappedSize",     uint32_t), #
        ("EntryRVA",       uint32_t), #
        ("Unk2C",          uint32_t), #
        ("Name",           char*16),  #
        ("Guid",           uint8_t*16), #
    ]

    def pprint(self):
        print "Module tag:        %s" % (self.Tag)
        nm = self.Name.rstrip('\0')
        print "Module name:       %s" % (nm)
        print "Guid:              %s" % (hexdump(self.Guid))
        print "Version:           %d.%d.%d.%d" % (self.MajorVersion, self.MinorVersion, self.HotfixVersion, self.BuildVersion)
        print "Unk04:             0x%08X" % (self.Unk04)
        print "Unk08:             0x%08X" % (self.Unk08)
        print "Unk14:             0x%08X" % (self.Unk14)
        print "Compressed size:   0x%08X" % (self.CompressedSize)
        print "Uncompressed size: 0x%08X" % (self.UncompressedSize)
        print "Mapped address:    0x%08X" % (self.LoadAddress)
        print "Mapped size:       0x%08X" % (self.MappedSize)
        print "Entrypoint RVA:    0x%08X (VA=%08X)" % (self.EntryRVA, self.EntryRVA+self.LoadAddress)
        print "Unk2C:             0x%08X" % (self.Unk2C)

MeModulePowerTypes = ["POWER_TYPE_RESERVED", "POWER_TYPE_M0_ONLY", "POWER_TYPE_M3_ONLY", "POWER_TYPE_LIVE"]
MeCompressionTypes = ["COMP_TYPE_NOT_COMPRESSED", "COMP_TYPE_HUFFMAN", "COMP_TYPE_LZMA", "<unknown>"]
COMP_TYPE_NOT_COMPRESSED = 0
COMP_TYPE_HUFFMAN = 1
COMP_TYPE_LZMA = 2
MeModuleTypes      = ["DEFAULT", "PRE_ME_KERNEL", "VENOM_TPM", "APPS_QST_DT", "APPS_AMT", "TEST"]
MeApiTypes         = ["API_TYPE_DATA", "API_TYPE_ROMAPI", "API_TYPE_KERNEL", "<unknown>"]

class MeModuleHeader2(ctypes.LittleEndianStructure):
    _fields_ = [
        ("Tag",            char*4),     # $MME
        ("Name",           char*16),    # 4
        ("Hash",           uint8_t*32), # 0x14
        ("ModBase",        uint32_t),   # 0x34
        ("Offset",         uint32_t),   # 0x38 From the start of manifest
        ("CodeSize",       uint32_t),   # 0x3C
        ("Size",           uint32_t),   # 0x40
        ("MemorySize",     uint32_t),   # 0x44
        ("PreUmaSize",     uint32_t),   # 0x48
        ("EntryPoint",     uint32_t),   # 0x4C
        ("Flags",          uint32_t),   # 0x50
        ("Unk54",          uint32_t),   #
        ("Unk58",          uint32_t),   #
        ("Unk5C",          uint32_t),   #
    ]

    def comptype(self):
        return (self.Flags>>4)&7

    def print_flags(self):
        print "    LoadState:           %d" % ((self.Flags>>0)&1)
        powtype = (self.Flags>>1)&3
        print "    Power Type:          %s (%d)" % (MeModulePowerTypes[powtype], powtype)
        print "    UMA Dependency:      %d" % ((self.Flags>>3)&1)
        comptype = (self.Flags>>4)&7
        print "    Compression:         %s (%d)" % (MeCompressionTypes[comptype], comptype)
        modstage = (self.Flags>>7)&0xF
        if modstage < len(MeModuleTypes):
            smtype = MeModuleTypes[modstage]
        else:
            smtype = "STAGE %X" % modstage
        print "    Load Stage:          %s (%d)" % (smtype, modstage)
        apitype = (self.Flags>>11)&7
        print "    API Type:            %s (%d)" % (MeApiTypes[apitype], apitype)

        print "    Load:                %d" % ((self.Flags>>14)&1)
        print "    Initialize:          %d" % ((self.Flags>>15)&1)
        print "    Privileged:          %d" % ((self.Flags>>16)&1)
        print "    Alias1 Pages (RAPI): %d" % ((self.Flags>>17)&7)
        print "    Alias2 Pages (KAPI): %d" % ((self.Flags>>20)&3)
        print "    Pre-UMA Load:        %d" % ((self.Flags>>22)&1)
        if self.Flags >> 23:
            print "    Unknown B23_31: %d" % ((self.Flags>>23))

    def pprint(self):
        print "Header tag:     %s" % (self.Tag)
        nm = self.Name.rstrip('\0')
        print "Module name:    %s" % (nm)
        print "Hash:           %s" % (hexdump(self.Hash))
        print "Module base:    0x%08X" % (self.ModBase)
        print "Offset:         0x%08X" % (self.Offset)
        print "Code size:      0x%08X" % (self.CodeSize)
        print "Data length:    0x%08X" % (self.Size)
        print "Memory size:    0x%08X" % (self.MemorySize)
        print "Pre-UMA size:   0x%08X" % (self.PreUmaSize)
        print "Entry point:    0x%08X" % (self.EntryPoint)
        print "Flags:          0x%08X" % (self.Flags)
        self.print_flags()
        print "Unk54:          0x%08X" % (self.Unk54)
        print "Unk58:          0x%08X" % (self.Unk58)
        print "Unk5C:          0x%08X" % (self.Unk5C)

    def print_map(self):
        nm = self.Name.rstrip('\0').ljust(16, ' ')
        base = self.ModBase
        rapi1 = ((self.Flags>>17)&7)
        rapi2 = ((self.Flags>>20)&3)
        codestart = base + (rapi1+rapi2) * 0x1000
        codeend = base + self.CodeSize
        dataend = base + self.MemorySize
        curoff = base
        if rapi1:
            rapi1end = curoff + rapi1 * 0x1000
            print "%08X %08X  %s RAPI" % (curoff, rapi1end, nm)
            curoff = rapi1end
        if rapi2:
            rapi2end = curoff + rapi2 * 0x1000
            print "%08X %08X  %s KAPI" % (curoff, rapi2end, nm)
            curoff = rapi2end
        if self.PreUmaSize == 0:
            codestart = base
        if codestart:
            if curoff < codestart:
                print "%08X %08X  %s GAP" % (curoff, codestart, nm)
                curoff = codestart
            print "%08X %08X  %s CODE" % (curoff, codeend, nm)
            curoff = codeend
        if curoff < dataend:
            print "%08X %08X  %s DATA" % (curoff, dataend, nm)
            curoff = dataend
        if curoff & 0xFFF:
            gapend = (curoff + 0xFFF) & ~0xFFF
            print "%08X %08X  %s GAP" % (curoff, gapend, nm)
            curoff = gapend

def extract_code_mods(nm, f, soff):
    try:
       os.mkdir(nm)
    except:
       pass
    os.chdir(nm)
    print " extracting CODE partition %s" % (nm)
    if f[soff:soff+4]=='$CPD':
     s= CPDHeader
    else:
     s= MeManifestHeader
    manif = get_struct(f, soff, s)
    manif.parse_mods(f, soff)
    manif.pprint()
    manif.extract(f, soff)
    os.chdir("..")


def decomp_lzma(compdata):

    if os.name == "posix":
        import subprocess
    elif os.name == "nt":
        import subprocess, _subprocess
    else:
        import subprocess, _subprocess

    if os.name == "nt":
        # hide the console window
        si = subprocess.STARTUPINFO()
        si.dwFlags |= _subprocess.STARTF_USESHOWWINDOW

    if in_ida:
        basedir = idaapi.idadir("loaders")
    else:
        basedir = os.path.dirname(__file__)
    path = os.path.join(basedir, "lzma")
    #print "using decompressor at '%s'" % path
    try:
        process = subprocess.Popen([path, "d", "-si", "-so"], startupinfo=si, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, errout = process.communicate(compdata)
        retcode = process.poll()
    except IOError as e:
        print "error %d running lzma!\nstderr output:\n%s" % (e.errno, errout)
        return None
    except OSError as e:
        print "Error running lzma.exe (error %d: %s)" % (e.errno, e.strerror)
        return None
    except:
        print "Error running lzma.exe"
        return None
    if retcode:
        return None
    return output

class MeManifestHeader(ctypes.LittleEndianStructure):
    _fields_ = [
        ("ModuleType",     uint16_t), # 00
        ("ModuleSubType",  uint16_t), # 02
        ("HeaderLen",      uint32_t), # 04 in dwords
        ("HeaderVersion",  uint32_t), # 08
        ("Flags",          uint32_t), # 0C 0x80000000 = Debug
        ("ModuleVendor",   uint32_t), # 10
        ("Date",           uint32_t), # 14 BCD yyyy.mm.dd
        ("Size",           uint32_t), # 18 in dwords
        ("Tag",            char*4),   # 1C $MAN or $MN2
        ("NumModules",     uint32_t), # 20
        ("MajorVersion",   uint16_t), # 24
        ("MinorVersion",   uint16_t), # 26
        ("HotfixVersion",  uint16_t), # 28
        ("BuildVersion",   uint16_t), # 2A
        ("Unknown1",       uint32_t*19), # 2C
        ("KeySize",        uint32_t), # 78
        ("ScratchSize",    uint32_t), # 7C
        ("RsaPubKey",      uint32_t*64), # 80
        ("RsaPubExp",      uint32_t),    # 180
        ("RsaSig",         uint32_t*64), # 184
        ("PartitionName",  char*12),    # 284
        # 290
    ]

    def parse_mods(self, f, offset):
        self.modules = []
        self.updparts = []
        orig_off = offset
        offset += self.HeaderLen*4
        offset += 12
        if self.Tag == '$MN2':
            self.cpu = "ARCompact"
            htype = MeModuleHeader2
            hdrlen = ctypes.sizeof(htype)
            if self.NumModules > 1:
                # check for TXE
                if f[offset+hdrlen:offset+hdrlen+4] != '$MME':
                    hdrlen = 0x80
                    if f[offset+hdrlen:offset+hdrlen+4] == '$MME':
                        print "TXE firmware detected"
                        self.cpu = "SPARC"
                    else:
                        raise Exception("Could not determine module header length!")
            udc_fmt = "<4s32s16sII"
            udc_len = 0x3C
        elif self.Tag == '$MAN':
            self.cpu = "ARC"
            htype = MeModuleHeader1
            hdrlen = ctypes.sizeof(htype)
            udc_fmt = "<4s20s16sII"
            udc_len = 0x30
        else:
            print ("Don't know how to parse modules for manifest tag %s!" % self.Tag)
            self.huff_start =0
            self.huff_end =0
            return
            raise Exception("Don't know how to parse modules for manifest tag %s!" % self.Tag)

        modmap = {}
        self.huff_start = 0
        for i in range(self.NumModules):
            mod = get_struct(f, offset, htype)
            if not mod.Tag in ['$MME', '$MDL']:
                raise Exception("Bad module tag (%s) at offset %08X!" % (mod.Tag, offset))
            nm = mod.Name.rstrip('\0')
            modmap[nm] = mod
            self.modules.append(mod)
            if mod.comptype() == COMP_TYPE_HUFFMAN:
                if self.huff_start and self.huff_start != mod.Offset:
                    print "Warning: inconsistent start offset for Huffman modules!"
                self.huff_start = mod.Offset
            offset += hdrlen

        self.partition_end = None
        hdr_end = orig_off + self.Size*4
        while offset < hdr_end:
            # print "tags %08X" % offset
            hdr = f[offset:offset+8]
            if hdr == '\xFF' * 8:
                offset += hdrlen
                continue
            if len(hdr) < 8 or hdr[0] != '$':
                break
            tag, elen = hdr[:4], struct.unpack("<I", hdr[4:])[0]
            if elen == 0:
                break
            print "Tag: %s, data length: %08X (0x%08X bytes)" % (tag, elen, elen*4)
            if tag == '$UDC':
                subtag, hash, subname, suboff, size = struct.unpack(udc_fmt, f[offset+8:offset+8+udc_len])
                suboff += offset
                print "Update code part: %s, %s, offset %08X, size %08X" % (subtag, subname.rstrip('\0'), suboff, size)
                self.updparts.append((subtag, suboff, size))
            elif tag == '$GLT':
                suboff, size = struct.unpack("<II", f[offset+8:offset+16])
                print "GLUT part: offset +%08X, size %08X" % (suboff, size)
                self.updparts.append(('GLUT', offset+suboff, size))
            elif elen == 3:
                val = struct.unpack("<I", f[offset+8:offset+12])[0]
                print "%s: %08X" % (tag[1:], val)
            elif elen == 4:
                vals = struct.unpack("<II", f[offset+8:offset+16])
                print "%s: %08X %08X" % (tag[1:], vals[0], vals[1])
            else:
                vals = array.array("I", f[offset+8:offset+elen*4])
                print "%s: %s" % (tag[1:], " ".join("%08X" % v for v in vals))
                if tag == '$MCP':
                    self.partition_end = vals[0] + vals[1]
            offset += elen*4

        offset = hdr_end
        while True:
            print "mods %08X" % offset
            if f[offset:offset+4] != '$MOD':
                break
            mfhdr = get_struct(f, offset, MeModuleFileHeader1)
            mfhdr.pprint()
            nm = mfhdr.Name.rstrip('\0')
            mod = modmap[nm]
            # copy some fields needed by other code
            mod.Offset = offset - orig_off
            mod.UncompressedSize = mfhdr.UncompressedSize
            mod.ModBase = mfhdr.LoadAddress
            mod.CodeSize = mfhdr.UncompressedSize
            mod.MemorySize = mfhdr.MappedSize
            mod.PreUmaSize = mod.MemorySize
            mod.EntryPoint = mod.ModBase + mfhdr.EntryRVA
            offset += mod.Size

        # check for huffman LUT
        offset = self.huff_start
        if f[offset+1:offset+4] == 'LUT':
            cnt, unk8, unkc, complen = struct.unpack("<IIII", f[offset+4:offset+20])
            self.huff_end = offset + 0x40 + 4*cnt + complen
        else:
            self.huff_start = 0xFFFFFFFF
            self.huff_end = 0xFFFFFFFF

    def print_mods(self):
        pname = self.PartitionName.rstrip('\0')
        print "------%s------" % pname
        for i, mod in enumerate(self.modules):
            if i: print "--"
            mod.print_map()
        print "------End-------\n"
        for subtag, soff, subsize in self.updparts:
            if subtag != 'GLUT':
                manif = get_struct(f, soff, MeManifestHeader)
                manif.parse_mods(f, soff)
                manif.print_mods()

    def _get_mod_data(self, f, offset, imod):
        huff_end = self.huff_end
        nhuffs = 0
        for mod in self.modules:
            if mod.comptype() != COMP_TYPE_HUFFMAN:
                huff_end = min(huff_end, mod.Offset)
            else:
                nhuffs += 1
        mod = self.modules[imod]
        nm = mod.Name.rstrip('\0')
        islast = (imod == len(self.modules)-1)
        if mod.Offset in [0xFFFFFFFF, 0] or (mod.Size in [0xFFFFFFFF, 0] and not islast and mod.comptype() != COMP_TYPE_HUFFMAN):
            return None
        else:
            soff = offset + mod.Offset
            size = mod.Size
            data = f[soff:soff+size]
            if mod.comptype() == COMP_TYPE_LZMA:
                ext = "lzma"
                if data.startswith("\x36\x00\x40\x00\x00") and data[0xE:0x11] == '\x00\x00\x00':
                    # delete the extra zeroes so the stream can be decompressed
                    data = data[:0xE] + data[0x11:]
                ud = decomp_lzma(data)
                if ud:
                    data = ud
                    ext = "bin"
            elif mod.comptype() == COMP_TYPE_HUFFMAN:
                ext = "huff"
                if nhuffs != 1:
                    nm = self.PartitionName
                size = huff_end - mod.Offset
            else:
                ext = "bin"
            if self.Tag == '$MAN':
                ext = "mod"
                moff = soff+0x50
                if f[moff:moff+5] == '\x5D\x00\x00\x80\x00':
                    data = f[moff:moff+5] + struct.pack("<Q", mod.UncompressedSize) + f[moff+5:moff+mod.Size-0x50]
                    # file("%s_comp.lzma" % nm, "wb").write(data)
                    ud = decomp_lzma(data)
                    if ud:
                        data = f[soff:soff+0x50] + ud
                        ext = "bin"
            return (data, ext)

    def extract(self, f, offset):
        huff_end = self.huff_end
        nhuffs = 0
        for mod in self.modules:
            if mod.comptype() != COMP_TYPE_HUFFMAN:
                huff_end = min(huff_end, mod.Offset)
            else:
                print "Huffman module:      %r %08X/%08X" % (mod.Name.rstrip('\0'), mod.ModBase, mod.CodeSize)
                nhuffs += 1
        for imod, mod in enumerate(self.modules):
            mod = self.modules[imod]
            nm = mod.Name.rstrip('\0')
            islast = (imod == len(self.modules)-1)
            # print "Module:      %r %08X/%08X" % (nm, mod.ModBase, mod.CodeSize),
            print "Module:      %r" % (nm),
            r = self._get_mod_data(f, offset, imod)
            if r:
                data, ext = r
                if ext == "huff" and nhuffs != 1:
                    nm = self.PartitionName
                if ext!= "bin":
                   fname = "%s_mod.%s" % (nm, ext)
                else:
                   fname = nm
                print " => %s" % (fname)
                open(fname, "wb").write(data)

        for subtag, soff, subsize in self.updparts:
            fname = "%s_udc.bin" % subtag
            print "Update part: %r %08X/%08X" % (subtag, soff, subsize),
            print " => %s" % (fname)
            open(fname, "wb").write(f[soff:soff+subsize])
            if subtag != 'GLUT':
                extract_code_mods(subtag, f, soff)

    def pprint(self):
        print "Module Type: %d, Subtype: %d" % (self.ModuleType, self.ModuleSubType)
        print "Header Length:       0x%02X (0x%X bytes)" % (self.HeaderLen, self.HeaderLen*4)
        print "Header Version:      %d.%d" % (self.HeaderVersion>>16, self.HeaderVersion&0xFFFF)
        print "Flags:               0x%08X" % (self.Flags),
        print " [%s signed] [%s flag]" % (["production","debug"][(self.Flags>>31)&1], ["production","pre-production"][(self.Flags>>30)&1])
        print "Module Vendor:       0x%04X" % (self.ModuleVendor)
        print "Date:                %08X" % (self.Date)
        print "Total Manifest Size: 0x%02X (0x%X bytes)" % (self.Size, self.Size*4)
        print "Tag:                 %s" % (self.Tag)
        print "Number of modules:   %d" % (self.NumModules)
        print "Version:             %d.%d.%d.%d" % (self.MajorVersion, self.MinorVersion, self.HotfixVersion, self.BuildVersion)
        print "Unknown data 1:      %s" % ([n for n in self.Unknown1])
        print "Key size:            0x%02X (0x%X bytes)" % (self.KeySize, self.KeySize*4)
        print "Scratch size:        0x%02X (0x%X bytes)" % (self.ScratchSize, self.ScratchSize*4)
        print "RSA Public Key:      [skipped]"
        print "RSA Public Exponent: %d" % (self.RsaPubExp)
        print "RSA Signature:       [skipped]"
        pname = self.PartitionName.rstrip('\0')
        if not pname:
            pname = "(none)"
        print "Partition name:      %s" % (pname)
        print "---Modules---"
        for mod in self.modules:
            mod.pprint()
            print
        print "------End-------"


class CPDEntry(ctypes.LittleEndianStructure):
    _fields_ = [
        ("Name",           char*12),  # 00 
        ("Offset",         uint32_t), # 04
        ("Size",         uint32_t), # 08
        ("Flags",          uint32_t), #0C
        # 10
    ]
    def comptype(self):
        nm = self.Name.rstrip('\0')
        typ = self.Offset>>24
        self.ModBase =0
        self.CodeSize =0
        if nm[-4:-3]=='.': return COMP_TYPE_NOT_COMPRESSED
        if typ==2: return COMP_TYPE_HUFFMAN
        elif typ==0: return COMP_TYPE_LZMA
        else:  return COMP_TYPE_NOT_COMPRESSED

    def pprint(self):
        nm = self.Name.rstrip('\0')
        print "Module name:    %s" % (nm)
        typ = self.Offset>>28
        print "Offset: %08X" % (self.Offset & 0xFFFFFF)
        print "Compress flag: %08X" % ((self.Offset >>25) &1)
        print "Size: %08X" % (self.Size)
        print "comp type:%d" %self.comptype()
        print "Flags: %08X"% (self.Flags)


class CPDHeader(ctypes.LittleEndianStructure):
    _fields_ = [
        ("Tag",         char*4),   # 00 $CPD
        ("NumModules",   uint32_t), # 04
        ("HeaderVersion",uint8_t), # 08
        ("EntryVersion", uint8_t), # 09
        ("HeaderLength", uint8_t), # 0A
        ("Checksum",     uint8_t), # 0B
        ("PartitionName", char*4),    #0C
        # 10
    ]

    def parse_mods(self, f, offset):
        self.modules = []
        self.updparts = []
        orig_off = offset
        offset += 0x10
        if self.Tag == '$MN2':
            self.cpu = "ARCompact"
            htype = MeModuleHeader2
            hdrlen = ctypes.sizeof(htype)
            udc_fmt = "<4s32s16sII"
            udc_len = 0x3C
        elif self.Tag == '$MAN':
            self.cpu = "ARC"
            htype = MeModuleHeader1
            hdrlen = ctypes.sizeof(htype)
            udc_fmt = "<4s20s16sII"
            udc_len = 0x30
        elif self.Tag == '$CPD':
            self.cpu = "metapc"
            htype = CPDEntry
            hdrlen = ctypes.sizeof(htype)
            udc_fmt = "<4s20s16sII"
            udc_len = 0x30
        else:
            print ("Don't know how to parse modules for manifest tag %r!" % self.Tag)
            self.huff_start =0
            self.huff_end =0
            return
            raise Exception("Don't know how to parse modules for manifest tag %s!" % self.Tag)

        modmap = {}
        self.huff_start = 0
        for i in range(self.NumModules):
            mod = get_struct(f, offset, htype)
            nm = mod.Name.rstrip('\0')
            modmap[nm] = mod
            self.modules.append(mod)
            if mod.comptype() == COMP_TYPE_HUFFMAN:
                if self.huff_start and self.huff_start != mod.Offset:
                    print "Warning: inconsistent start offset for Huffman modules!"
                self.huff_start = mod.Offset
            offset += hdrlen

        self.partition_end = None
        hdr_end = offset
        while offset < hdr_end:
            # print "tags %08X" % offset
            hdr = f[offset:offset+8]
            if hdr == '\xFF' * 8:
                offset += hdrlen
                continue
            if len(hdr) < 8 or hdr[0] != '$':
                break
            tag, elen = hdr[:4], struct.unpack("<I", hdr[4:])[0]
            if elen == 0:
                break
            print "Tag: %s, data length: %08X (0x%08X bytes)" % (tag, elen, elen*4)
            if tag == '$UDC':
                subtag, hash, subname, suboff, size = struct.unpack(udc_fmt, f[offset+8:offset+8+udc_len])
                suboff += offset
                print "Update code part: %s, %s, offset %08X, size %08X" % (subtag, subname.rstrip('\0'), suboff, size)
                self.updparts.append((subtag, suboff, size))
            elif tag == '$GLT':
                suboff, size = struct.unpack("<II", f[offset+8:offset+16])
                print "GLUT part: offset +%08X, size %08X" % (suboff, size)
                self.updparts.append(('GLUT', offset+suboff, size))
            elif elen == 3:
                val = struct.unpack("<I", f[offset+8:offset+12])[0]
                print "%s: %08X" % (tag[1:], val)
            elif elen == 4:
                vals = struct.unpack("<II", f[offset+8:offset+16])
                print "%s: %08X %08X" % (tag[1:], vals[0], vals[1])
            else:
                vals = array.array("I", f[offset+8:offset+elen*4])
                print "%s: %s" % (tag[1:], " ".join("%08X" % v for v in vals))
                if tag == '$MCP':
                    self.partition_end = vals[0] + vals[1]
            offset += elen*4

        offset = hdr_end
        while True:
            print "mods %08X" % offset
            if f[offset:offset+4] != '$MOD':
                break
            mfhdr = get_struct(f, offset, MeModuleFileHeader1)
            mfhdr.pprint()
            nm = mfhdr.Name.rstrip('\0')
            mod = modmap[nm]
            # copy some fields needed by other code
            mod.Offset = offset - orig_off
            mod.UncompressedSize = mfhdr.UncompressedSize
            mod.ModBase = mfhdr.LoadAddress
            mod.CodeSize = mfhdr.UncompressedSize
            mod.MemorySize = mfhdr.MappedSize
            mod.PreUmaSize = mod.MemorySize
            mod.EntryPoint = mod.ModBase + mfhdr.EntryRVA
            offset += mod.Size

        # check for huffman LUT
        offset = self.huff_start
        if f[offset+1:offset+4] == 'LUT':
            cnt, unk8, unkc, complen = struct.unpack("<IIII", f[offset+4:offset+20])
            self.huff_end = offset + 0x40 + 4*cnt + complen
        else:
            self.huff_start = 0xFFFFFFFF
            self.huff_end = 0xFFFFFFFF

    def print_mods(self):
        pname = self.PartitionName.rstrip('\0')
        print "------%s------" % pname
        for i, mod in enumerate(self.modules):
            if i: print "--"
            mod.print_map()
        print "------End-------\n"
        for subtag, soff, subsize in self.updparts:
            if subtag != 'GLUT':
                manif = get_struct(f, soff, MeManifestHeader)
                manif.parse_mods(f, soff)
                manif.print_mods()

    def _get_mod_data(self, f, offset, imod):
        huff_end = self.huff_end
        nhuffs = 0
        for mod in self.modules:
            if mod.comptype() != COMP_TYPE_HUFFMAN:
                huff_end = min(huff_end, mod.Offset)
            else:
                nhuffs += 1
        mod = self.modules[imod]
        nm = mod.Name.rstrip('\0')
        islast = (imod == len(self.modules)-1)
        if mod.Offset in [0xFFFFFFFF, 0] or (mod.Size in [0xFFFFFFFF, 0] and not islast and mod.comptype() != COMP_TYPE_HUFFMAN):
            return None
        else:
            if self.Tag == '$CPD':
              soff = offset + mod.Offset & 0xFFFFFF
            else:            
              soff = offset + mod.Offset
            size = mod.Size
            data = f[soff:soff+size]
            if mod.comptype() == COMP_TYPE_LZMA and nm[-4:-3] !='.':
                ext = "lzma"
                if data.startswith("\x36\x00\x40\x00\x00") and data[0xE:0x11] == '\x00\x00\x00':
                    # delete the extra zeroes so the stream can be decompressed
                    data = data[:0xE] + data[0x11:]
                ud = decomp_lzma(data)
                if ud:
                    data = ud
                    ext = "bin"
            elif mod.comptype() == COMP_TYPE_HUFFMAN:
                ext = "huff"
                if nhuffs != 1:
                    nm = self.PartitionName
                size = huff_end - mod.Offset
            else:
                ext = "bin"
            if self.Tag == '$MAN':
                ext = "mod"
                moff = soff+0x50
                if f[moff:moff+5] == '\x5D\x00\x00\x80\x00':
                    data = f[moff:moff+5] + struct.pack("<Q", mod.UncompressedSize) + f[moff+5:moff+mod.Size-0x50]
                    # file("%s_comp.lzma" % nm, "wb").write(data)
                    ud = decomp_lzma(data)
                    if ud:
                        data = f[soff:soff+0x50] + ud
                        ext = "bin"
            return (data, ext)

    def extract(self, f, offset):
        huff_end = self.huff_end
        nhuffs = 0
        for mod in self.modules:
            if mod.comptype() != COMP_TYPE_HUFFMAN:
                huff_end = min(huff_end, mod.Offset)
            else:
                print "Huffman module:      %r %08X/%08X" % (mod.Name.rstrip('\0'), mod.ModBase, mod.CodeSize)
                nhuffs += 1
        for imod, mod in enumerate(self.modules):
            mod = self.modules[imod]
            nm = mod.Name.rstrip('\0')
            islast = (imod == len(self.modules)-1)
            # print "Module:      %r %08X/%08X" % (nm, mod.ModBase, mod.CodeSize),
            print "Module:      %r" % (nm),
            r = self._get_mod_data(f, offset, imod)
            if r:
                data, ext = r
                if ext == "huff" and nhuffs != 1:
                    nm = self.PartitionName
                if ext != "bin":
                   fname = "%s_mod.%s" % (nm, ext)
                else:
                   fname = nm
                print " => %s" % (fname)
                open(fname, "wb").write(data)

        for subtag, soff, subsize in self.updparts:
            fname = "%s_udc.bin" % subtag
            print "Update part: %r %08X/%08X" % (subtag, soff, subsize),
            print " => %s" % (fname)
            open(fname, "wb").write(f[soff:soff+subsize])
            if subtag != 'GLUT':
                extract_code_mods(subtag, f, soff)

    def pprint(self):
        print "Tag:                 %s" % (self.Tag)
        print "Number of modules:   %d" % (self.NumModules)
        print "Header Version:     %0X" % (self.HeaderVersion)
        print "Entry Version:     %02X" % (self.EntryVersion)
        print "Header Length:     %02X" % (self.HeaderLength)
        print "Checksum:         %02X" % (self.Checksum)
        pname = self.PartitionName.rstrip('\0')
        if not pname:
            pname = "(none)"
        print "Partition name:      %s" % (pname)
        print "---Modules---"
        for mod in self.modules:
            mod.pprint()
            print
        print "------End-------"


PartTypes = ["Code", "BlockIo", "Nvram", "Generic", "Effs", "Rom"]

PT_CODE    = 0
PT_BLOCKIO = 1
PT_NVRAM   = 2
PT_GENERIC = 3
PT_EFFS    = 4
PT_ROM     = 5

class MeFptEntry(ctypes.LittleEndianStructure):
    _fields_ = [
        ("Name",            char*4),   # 00 partition name
        ("Owner",           char*4),   # 04 partition owner?
        ("Offset",          uint32_t), # 08 from the start of FPT, or 0
        ("Size",            uint32_t), # 0C
        ("TokensOnStart",   uint32_t), # 10
        ("MaxTokens",       uint32_t), # 14
        ("ScratchSectors",  uint32_t), # 18
        ("Flags",           uint32_t), # 1C
    ]
    #def __init__(self, f, offset):
        #self.sig1, self.Owner,  self.Offset, self.Size  = struct.unpack("<4s4sII", f[offset:offset+0x10])
        #self.TokensOnStart, self.MaxTokens, self.ScratchSectors, self.Flags = struct.unpack("<IIII", f[offset+0x10:offset+0x20])

    def ptype(self):
        return self.Flags & 0x7F

    def print_flags(self):
        pt = self.ptype()
        if pt < len(PartTypes):
            stype = "%d (%s)" % (pt, PartTypes[pt])
        else:
            stype = "%d" % pt
        print "    Type:         %s" % stype
        print "    DirectAccess: %d" % ((self.Flags>>7)&1)
        print "    Read:         %d" % ((self.Flags>>8)&1)
        print "    Write:        %d" % ((self.Flags>>9)&1)
        print "    Execute:      %d" % ((self.Flags>>10)&1)
        print "    Logical:      %d" % ((self.Flags>>11)&1)
        print "    WOPDisable:   %d" % ((self.Flags>>12)&1)
        print "    ExclBlockUse: %d" % ((self.Flags>>13)&1)


    def pprint(self):
        print "Partition:      %r" % self.Name
        print "Owner:          %s" % [repr(self.Owner), "(none)"][self.Owner == '\xFF\xFF\xFF\xFF']
        print "Offset/size:    %08X/%08X" % (self.Offset, self.Size)
        print "TokensOnStart:  %08X" % (self.TokensOnStart)
        print "MaxTokens:      %08X" % (self.MaxTokens)
        print "ScratchSectors: %08X" % (self.ScratchSectors)
        print "Flags:              %04X" % self.Flags
        self.print_flags()

class MeFptTable:
    def __init__(self, f, offset):
        hdr = f[offset:offset+0x30]
        if hdr[0x10:0x14] == '$FPT':
            self.rombjump = hdr[:0x10]
            base = offset + 0x10
        elif hdr[0:4] == '$FPT':
            base = offset
            self.rombjump = None
        else:
            raise Exception("FPT format not recognized")
        num_entries = DwordAt(f, base+4)
        self.BCDVer, self.FPTEntryType, self.HeaderLen, self.Checksum = struct.unpack("<BBBB", f[base+8:base+12])
        self.FlashCycleLifetime, self.FlashCycleLimit, self.UMASize   = struct.unpack("<HHI", f[base+12:base+20])
        x = struct.unpack("<I4H", f[base+20:base+32])
        self.Flags, self.ExtraVer = x[0], x[1:5]

        offset = base + 0x20
        self.parts = []
        for i in range(num_entries):
            part = get_struct(f, offset, MeFptEntry) #MeFptEntry(f, offset)
            offset += 0x20
            self.parts.append(part)

    def extract(self, f, offset):
        for ipart in range(len(self.parts)):
            part = self.parts[ipart]
            print "Partition:      %r %08X/%08X" % (part.Name, part.Offset, part.Size),
            islast = (ipart == len(self.parts)-1)
            if part.Offset in [0xFFFFFFFF, 0] or (part.Size in [0xFFFFFFFF, 0] and not islast):
                print " (skipping)"
            else:
                nm = part.Name.rstrip('\0')
                soff  = offset + part.Offset
                fname = "%s_part.bin" % (part.Name)
                fname = replace_bad(fname, map(chr, range(128, 256) + range(0, 32)))
                print " => %s" % (fname)
                open(fname, "wb").write(f[soff:soff+part.Size])
                if part.ptype() == PT_CODE:
                    extract_code_mods(nm, f, soff)

    def find_part(self, name):
        for part in self.parts:
            if part.Name == name:
                return part
        return None

    def pprint(self):
        print "===ME Flash Partition Table==="
        print "NumEntries: %d" % len(self.parts)
        print "Version:    %d.%d" % (self.BCDVer >> 4, self.BCDVer & 0xF)
        print "EntryType:  %02X"  % (self.FPTEntryType)
        print "HeaderLen:  %02X"  % (self.HeaderLen)
        print "Checksum:   %02X"  % (self.Checksum)
        print "FlashCycleLifetime: %d" % (self.FlashCycleLifetime)
        print "FlashCycleLimit:    %d" % (self.FlashCycleLimit)
        print "UMASize:    %d" % self.UMASize
        print "Flags:      %08X" % self.Flags
        print "    EFFS present:   %d" % (self.Flags&1)
        print "    ME Layout Type: %d" % ((self.Flags>>1)&0xFF)
        print "Extra ver:  %d.%d.%d.%d" % (self.ExtraVer)
        if self.rombjump:
            print "ROM Bypass instruction: %s" % hexdump(self.rombjump)
        print "---Partitions---"
        for part in self.parts:
            part.pprint()
            print
        print "------End-------"


region_names = ["Descriptor", "BIOS", "ME", "GbE", "PDR", "Region 5", "Region 6", "Region 7" ]
region_fnames =["Flash Descriptor", "BIOS Region", "ME Region", "GbE Region", "PDR Region", "Region 5", "Region 6", "Region 7" ]

def print_flreg(val, name):
    print "%s region:" % name
    lim  = ((val >> 4) & 0xFFF000)
    base = (val << 12) & 0xFFF000
    if lim == 0 and base == 0xFFF000:
        print "  [unused]"
        return None
    lim |= 0xFFF
    print "  %08X - %08X (0x%08X bytes)" % (base, lim, lim - base + 1)
    return (base, lim)

def parse_descr(f, offset, extract):
    mapoff = offset
    if f[offset+0x10:offset+0x14] == "\x5A\xA5\xF0\x0F":
      mapoff = offset + 0x10
    elif f[offset:offset+0x4] != "\x5A\xA5\xF0\x0F":
      return -1
    print "Flash Descriptor found at %08X" % offset
    FLMAP0, FLMAP1, FLMAP2 = struct.unpack("<III", f[mapoff+4:mapoff+0x10])
    nr   = (FLMAP0 >> 24) & 0x7
    frba = (FLMAP0 >> 12) & 0xFF0
    nc   = (FLMAP0 >>  8) & 0x3
    fcba = (FLMAP0 <<  4) & 0xFF0
    print "Number of regions: %d " % (nr+1)
    print "Number of components: %d" % (nc+1)
    print "FRBA: 0x%08X" % frba
    print "FCBA: 0x%08X" % fcba
    me_offset = -1
    if nr<2: nr=2 #assume ME region exists
    for i in range(nr+1):
        FLREG = struct.unpack("<I", f[offset + frba + i*4:offset + frba + i*4 + 4])[0]
        r = print_flreg(FLREG, region_names[i])
        if r:
            base, lim = r
            if i == 2:
                me_offset = offset + base
            if extract:
                fname = "%s.bin" % region_fnames[i]
                print " => %s" % (fname)
                open(fname, "wb").write(f[offset + base:offset + lim + 1])
    return me_offset

class AcManifestHeader(ctypes.LittleEndianStructure):
    _fields_ = [
        ("ModuleType",     uint16_t), # 00
        ("ModuleSubType",  uint16_t), # 02
        ("HeaderLen",      uint32_t), # 04 in dwords
        ("HeaderVersion",  uint32_t), # 08
        ("ChipsetID",      uint16_t), # 0C
        ("Flags",          uint16_t), # 0E 0x80000000 = Debug
        ("ModuleVendor",   uint32_t), # 10
        ("Date",           uint32_t), # 14 BCD yyyy.mm.dd
        ("Size",           uint32_t), # 18 in dwords
        ("Reserved1",      uint32_t), # 1C
        ("CodeControl",    uint32_t), # 20
        ("ErrorEntryPoint",uint32_t), # 24
        ("GDTLimit",       uint32_t), # 28
        ("GDTBasePtr",     uint32_t), # 2C
        ("SegSel",         uint32_t), # 30
        ("EntryPoint",     uint32_t), # 34
        ("Reserved2",      uint32_t*16), # 38
        ("KeySize",        uint32_t), # 78
        ("ScratchSize",    uint32_t), # 7C
        ("RsaPubKey",      uint32_t*64), # 80
        ("RsaPubExp",      uint32_t),    # 180
        ("RsaSig",         uint32_t*64), # 184
        # 284
    ]

    def pprint(self):
        print "Module Type: %d, Subtype: %d" % (self.ModuleType, self.ModuleSubType)
        print "Header Length:       0x%02X (0x%X bytes)" % (self.HeaderLen, self.HeaderLen*4)
        print "Header Version:      %d.%d" % (self.HeaderVersion>>16, self.HeaderVersion&0xFFFF)
        print "ChipsetID:           0x%04X" % (self.ChipsetID)
        print "Flags:               0x%04X" % (self.Flags),
        print " [%s signed] [%s flag]" % (["production","debug"][(self.Flags>>15)&1], ["production","pre-production"][(self.Flags>>14)&1])
        print "Module Vendor:       0x%04X" % (self.ModuleVendor)
        print "Date:                %08X" % (self.Date)
        print "Total Module Size:   0x%02X (0x%X bytes)" % (self.Size, self.Size*4)
        print "Reserved1:           0x%08X" % (self.Reserved1)
        print "CodeControl:         0x%08X" % (self.CodeControl)
        print "ErrorEntryPoint:     0x%08X" % (self.ErrorEntryPoint)
        print "GDTLimit:            0x%08X" % (self.GDTLimit)
        print "GDTBasePtr:          0x%08X" % (self.GDTBasePtr)
        print "SegSel:              0x%04X" % (self.SegSel)
        print "EntryPoint:          0x%08X" % (self.EntryPoint)
        print "Key size:            0x%02X (0x%X bytes)" % (self.KeySize, self.KeySize*4)
        print "Scratch size:        0x%02X (0x%X bytes)" % (self.ScratchSize, self.ScratchSize*4)
        print "RSA Public Key:      [skipped]"
        print "RSA Public Exponent: %d" % (self.RsaPubExp)
        print "RSA Signature:       [skipped]"
        print "------End-------"

class LutHeader(ctypes.LittleEndianStructure):
    _fields_ = [
        ("Signature",      uint8_t*4),# 00 'LLUT' or 'GLUT' or ' LUT'
        ("ChunkCount",     uint32_t), # 04 number of compressed chunks
        ("AddrBase",       uint32_t), # 08 base address of unpacked data
        ("SpiBase",        uint32_t), # 0C offset of the LUT in the ME region
        ("HuffLength",     uint32_t), # 10 Total length of the huff stream
        ("HuffStart",      uint32_t), # 14 offset of the Huff data in the ME region
        ("Flags",          uint32_t), # 18 bit0: enable 1K pages
        ("Reserved1",      uint32_t*5), # 1C
        ("PageSize",       uint32_t), # 30 how much (uncompressed) memory each chunk covers
        ("verMajor",       uint16_t), # 34 version of the compression tool
        ("verMinor",       uint16_t), # 36
        ("Chipset",        char*4),   # 38 'PCH ' or 'CPT '
        ("Revision",       char*4),   # 3C 'A0  '
        # 40
    ]

    def pprint(self):
        sig = "".join(map(chr, self.Signature))
        print "Signature:           %r" % (sig)
        print "Chunk count          %d" % (self.ChunkCount)
        print "Unpacked base        0x%08X (VA=0x%08X)" % (self.AddrBase, self.AddrBase+0x10000000)
        print "LUT base:            0x%08X" % (self.SpiBase)
        print "Huffman data length: 0x%08X" % (self.HuffLength)
        print "Huffman data start:  0x%08X" % (self.HuffStart)
        print "Flags:               0x%08X" % (self.Flags)
        print "Reserved1:           %s" % (list(self.Reserved1))
        print "Page size:           0x%08X" % (self.PageSize)
        print "Tool version:        %d.%d" % (self.verMajor, self.verMinor)
        print "Chipset/revision:    %s/%s" % (self.Chipset.rstrip(' '), self.Revision.rstrip(' '))
        print ""

def get_huff_range(f, offset):
    manif = get_struct(f, offset, MeManifestHeader)
    if manif.Tag != '$MN2':
        return

    huff_start = (manif.Size*4 + 0x3F) & ~0x3f
    hdr = get_struct(f, offset+huff_start, LutHeader)
    if list(hdr.Signature) == [0x4C, 0x4C, 0x55, 0x54]:
       # skip the header and chunk table
       huff_start = huff_start + 0x40 + hdr.ChunkCount*4

    orig_off = offset
    offset += manif.HeaderLen*4
    offset += 12

    htype = MeModuleHeader2
    hdrlen = ctypes.sizeof(htype)

    modstarts = []
    has_huff = False
    # print "hs %08X" % huff_start
    for i in range(manif.NumModules):
        mod = get_struct(f, offset, htype)
        if mod.Tag != '$MME':
            continue
        if mod.comptype() == COMP_TYPE_HUFFMAN:
            has_huff = True
        else:
            modstarts.append(mod.Offset)
            # print "ms %08X" % mod.Offset
        offset += hdrlen

    if not has_huff:
        return

    if modstarts:
        huff_end = min(modstarts)
    else:
        huff_end = huff_start + hdr.HuffLength
    return huff_start, huff_end

def dump_lut(f, me_offset, lut_offset, range_ends, extract, ftpr_range = None, nftp_range = None):
    hdr = get_struct(f, me_offset+lut_offset, LutHeader)
    print "LUT header at %08X:" % (lut_offset)
    hdr.pprint()
    if extract:
        tbloff = me_offset + lut_offset + 0x40
        vbase = hdr.AddrBase+0x10000000
        chunktbl = array.array("I", f[tbloff:tbloff+hdr.ChunkCount*4])
        tbl2 = set()
        tbl3 = {}

        print "Chunk table"
        print "index: offset  flag  vaddr"
        print "----  -------- ---- --------"
        for i, titem in enumerate(chunktbl):
            titem, fl = titem & 0x1FFFFFF, (titem >> 24) & 0xFE
            print "%04X: %08X  %02X  [%08X]" % (i, titem, fl, vbase + i*0x400)
            tbl2.add((titem, fl))
            tbl3[titem] = vbase + i*0x400
        if ftpr_range:
            tbl2 = sorted(tbl2)
            i = 0
            while tbl2[i][0] == 0:
              i += 1
            ftpr_off = ftpr_range[2]
            print "titem %d = %08X, ftpr huff start = %08X" % (i, tbl2[i][0], ftpr_range[0])
            print "ftpr partition start = %08X" % (tbl2[i][0] - ftpr_range[0])
            print "upd ftpr start = %08X" % (ftpr_off)
            delta = -(tbl2[i][0] - ftpr_range[0])
            huff_end = nftp_range[1] - delta + nftp_range[2]
            print "delta = %X, huff end offset = %X" % (delta, huff_end)
            tbl2.append((huff_end - ftpr_off, 0))
            delta += ftpr_off
            print "delta2 = %X" % (delta)
        else:
            delta = 0
            for h in range_ends:
                tbl2.add((h, 0))
            tbl2 = sorted(tbl2)
        of = open("unp_%08X.bin" % vbase, "wb")
        for i in range(1, len(tbl2)-1):
            titem, fl = tbl2[i]
            if titem in range_ends:
                continue
            itlen = tbl2[i+1][0] - titem
            file_off = me_offset+titem+delta
            # print " => file offset %08X" % file_off
            cdata = f[file_off:file_off+itlen]
            vaddr = tbl3[titem]
            print "%04X: %08X (vaddr=%08x, len=%08X, comp=%02X)" % (i, titem, vaddr, itlen, fl)
            if fl != 0x80 and extract:
                open("chunk_%08X_c%02X.huff" % (vaddr, fl), "wb").write(cdata)
                if fl == 0:
                    of.seek(vaddr-vbase)
                    of.write(cdata)
        of.close()

def dump_llut(f, me_offset, part_offset, name, extract):
    manif = get_struct(f, me_offset + part_offset, MeManifestHeader)
    lut_start = (manif.Size*4 + 0x3F) & ~0x3f
    lut_off = me_offset+part_offset+lut_start
    if f[lut_off+1:lut_off+4] != 'LUT':
        return
    huff_range = get_huff_range(f, me_offset + part_offset)
    if not huff_range:
        return
    huff_start, huff_end = huff_range
    print "%s huffman stream: %08X-%08X (%08X-%08X)" % (name, huff_start, huff_end, huff_start+part_offset, huff_end+part_offset)
    dirn = "%s_huff" % name
    if extract:
        try:
           os.mkdir(dirn)
        except:
           pass
        os.chdir(dirn)
    dump_lut(f, me_offset, part_offset+lut_start, [part_offset+huff_end], extract)
    if extract:
        os.chdir("..")

def dump_glut(f, me_offset, extract):
    fpt = MeFptTable(f, me_offset)
    glut_part = fpt.find_part('GLUT')
    if not glut_part:
        return

    # find out the huffman stream ranges
    ftpr_part = fpt.find_part('FTPR')
    nftp_part = fpt.find_part('NFTP')

    ftpr_range = get_huff_range(f, me_offset + ftpr_part.Offset)
    nftp_range = get_huff_range(f, me_offset + nftp_part.Offset)
    #print "FTPR huffman stream: %08X-%08X (%08X-%08X)" % (ftpr_range[0], ftpr_range[1], ftpr_range[0] + ftpr_part.Offset, ftpr_range[1] + ftpr_part.Offset)
    #print "NFTP huffman stream: %08X-%08X (%08X-%08X)" % (nftp_range[0], nftp_range[1], nftp_range[0] + nftp_part.Offset, nftp_range[1] + nftp_part.Offset)

    huff_end1 = ftpr_range[1] + ftpr_part.Offset
    huff_end2 = nftp_range[1] + nftp_part.Offset

    if extract:
        try:
           os.mkdir("GLUT_huff")
        except:
           pass
        os.chdir("GLUT_huff")
    dump_lut(f, me_offset, glut_part.Offset, [huff_end1, huff_end2], extract)
    if extract:
        os.chdir("..")

def dump_glut_upd(f, me_offset, extract):
    manif = get_struct(f, me_offset, MeManifestHeader)
    manif.parse_mods(f, me_offset)
    if len(manif.updparts) != 3:
        return
    for subtag, soff, subsize in manif.updparts:
        if subtag == 'GLUT':
            glut_start = soff
        elif subtag == 'FTPR':
            ftpr_off = soff
        elif subtag == 'NFTP':
            nftp_off = soff

    ftpr_range = get_huff_range(f, me_offset + ftpr_off)
    ftpr_range = (ftpr_range[0], ftpr_range[1], ftpr_off)
    nftp_range = get_huff_range(f, me_offset + nftp_off)
    nftp_range = (nftp_range[0], nftp_range[1], nftp_off)

    print "FTPR huffman stream: %08X-%08X (%08X-%08X)" % (ftpr_range[0], ftpr_range[1], ftpr_range[0] + ftpr_off, ftpr_range[1] + ftpr_off)
    print "NFTP huffman stream: %08X-%08X (%08X-%08X)" % (nftp_range[0], nftp_range[1], nftp_range[0] + nftp_off, nftp_range[1] + nftp_off)

    huff_end1 = ftpr_range[1] + ftpr_off
    huff_end2 = nftp_range[1] + nftp_off

    if extract:
        try:
           os.mkdir("GLUT_huff")
        except:
           pass
        os.chdir("GLUT_huff")
    dump_lut(f, me_offset, glut_start, [huff_end1, huff_end2], extract, ftpr_range, nftp_range)
    if extract:
        os.chdir("..")

try:
  # check if we are running under IDA
  import idaapi, struct
  from idc import *
  in_ida = True
except:
  # not run by IDA
  in_ida = False

# -----------------------------------------------------------------------
# called by IDA to see if loader accepts this file
def accept_file(li, n):
    if n > 0:
        return 0

    offset = li.tell()
    try:
        f = li.read(0x1000)
        fpt = MeFptTable(f, 0)
        for p in fpt.parts:
            if p.ptype() == PT_CODE:
                poff = offset + p.Offset
                li.seek(poff)
                manif = read_struct(li, MeManifestHeader)
                desc = "Intel ME firmware (FPT image, version %d.%d.%d.%d)" % (manif.MajorVersion, manif.MinorVersion, manif.HotfixVersion, manif.BuildVersion)
                return {'format': desc, 'options': 1}
    except:
        #print "exception!"
        #import traceback
        #traceback.print_exc()
        return 0

def myAddSeg(startea, endea, name, clas):
    base = 0
    use32 = 1
    s = idaapi.segment_t()
    s.startEA     = startea
    s.endEA       = endea
    s.sel         = idaapi.setup_selector(base)
    s.bitness     = use32
    s.align       = idaapi.saRelPara
    s.comb        = idaapi.scPub
    idaapi.add_segm_ex(s, name, clas, idaapi.ADDSEG_NOSREG|idaapi.ADDSEG_OR_DIE)

# -----------------------------------------------------------------------
# called by IDA to see if actually load the file
def load_mod(mod, data):
    nm = mod.Name.rstrip('\0')
    if mod.Tag == '$MME':
        base = mod.ModBase
        rapi1 = ((mod.Flags>>17)&7)
        rapi2 = ((mod.Flags>>20)&3)
        codestart = base + (rapi1+rapi2) * 0x1000
        codeend = base + mod.CodeSize
        dataend = base + mod.MemorySize
        entry   = mod.EntryPoint
    else:
        base = mod.LoadAddress
        rapi1 = rapi2 = 0
        codestart = base
        codeend = base + mod.UncompressedSize
        dataend = base + mod.MappedSize
        entry   = base + EntryRVA

    curoff = base
    if rapi1:
        rapi1end = curoff + rapi1 * 0x1000
        print "%08X %08X  %s RAPI" % (curoff, rapi1end, nm)
        myAddSeg(curoff, rapi1end, nm + ".RAPI", "CODE")
        curoff = rapi1end
    if rapi2:
        rapi2end = curoff + rapi2 * 0x1000
        print "%08X %08X  %s KAPI" % (curoff, rapi2end, nm)
        myAddSeg(curoff, rapi2end, nm + ".KAPI", "CODE")
        curoff = rapi2end
    if mod.PreUmaSize == 0:
        codestart = base
    if codestart:
        if curoff < codestart:
            print "%08X %08X  %s GAP" % (curoff, codestart, nm)
            curoff = codestart
        print "%08X %08X  %s CODE" % (curoff, codeend, nm)
        myAddSeg(codestart, codeend, nm + ".CODE", "CODE")
        print "data start: %s" % data[:4].encode('hex')
        idaapi.put_many_bytes(curoff, data[0:codeend-codestart])
        curoff = codeend
    if curoff < dataend:
        print "%08X %08X  %s DATA" % (curoff, dataend, nm)
        myAddSeg(curoff, dataend, nm + ".DATA", "DATA")
        idaapi.put_many_bytes(curoff, data[codeend-codestart:dataend-codestart])
        curoff = dataend
    if curoff & 0xFFF:
        gapend = (curoff + 0xFFF) & ~0xFFF
        print "%08X %08X  %s GAP" % (curoff, gapend, nm)
        curoff = gapend
    if entry != 0:
        makecode = len(data) > 0
        AddEntryPoint(mod.EntryPoint, mod.EntryPoint, nm + "_entry", makecode)

# -----------------------------------------------------------------------
def load_file(li, neflags, format):
    cpu_set = False
    sz = li.seek(0, 2)
    li.seek(0)
    f = li.read(sz)
    offset = 0
    fpt = MeFptTable(f, offset)
    manifs = []
    for p in fpt.parts:
        if p.ptype() == PT_CODE:
            poff = offset + p.Offset
            manif = get_struct(f, poff, MeManifestHeader)
            manif.parse_mods(f, poff)
            if not cpu_set:
                cpuname = manif.cpu
                if cpuname == "ARCompact":
                    cpuname = "arcmpct"
                elif cpuname == "SPARC":
                    cpuname = "sparcb"
                idaapi.set_processor_type(cpuname, idaapi.SETPROC_ALL|idaapi.SETPROC_FATAL)
                cpu_set = True
            for idx, mod in enumerate(manif.modules):
                data, ext = manif._get_mod_data(f, poff+offset, idx)
                if ext == "huff":
                    data = ""
                load_mod(mod, data)

    SetShortPrm(INF_AF2, GetShortPrm(INF_AF2) & ~(AF2_FTAIL|AF2_ANORET))

    return 1

if __name__ == '__main__' and not in_ida:
    if len(sys.argv) > 2 and sys.argv[1] == '--test-loader':
        li = open(sys.argv[2], "rb")
        print accept_file(li, 0)
        sys.exit(0)

    print "Intel ME dumper/extractor v0.3"
    if len(sys.argv) < 2:
        print "Usage: me_unpack.py MeImage.bin [-x] [offset]"
        print "   -x: extract ME partitions and code modules"
        print "   -h: dump Huffman-compressed chunks"
        print "   -m: print module map"
    else:
        fname = sys.argv[1]
        extract = False
        extract_huff = False
        print_modmap = False
        offset = 0
        for opt in sys.argv[2:]:
            if opt == "-x":
                extract = True
            elif opt == "-h":
                extract_huff = True
            elif opt == "-m":
                print_modmap = True
            else:
                offset = int(opt, 16)
        f = open(fname, "rb").read()
        off2 = parse_descr(f, offset, extract)
        if off2 != -1:
            offset = off2
            try:
               os.mkdir("ME Region")
            except:
               pass
            os.chdir("ME Region")
        manifs = []
        if f[offset:offset+8] == "\x04\x00\x00\x00\xA1\x00\x00\x00":
            while True:
                manif = get_struct(f, offset, MeManifestHeader)
                manif.parse_mods(f, offset)
                manif.pprint()
                manifs.append(manif)
                if extract:
                    manif.extract(f, offset)
                dump_glut_upd(f, offset, extract_huff)
                if manif.partition_end:
                    offset += manif.partition_end
                    print "Next partition: +%08X (%08X)" % (manif.partition_end, offset)
                else:
                    break
                if f[offset:offset+8] != "\x04\x00\x00\x00\xA1\x00\x00\x00":
                    break

        elif f[offset:offset+8] in ["\x02\x00\x00\x00\xA1\x00\x00\x00", "\x02\x00\x03\x00\xA1\x00\x00\x00"]:
            manif = get_struct(f, offset, AcManifestHeader)
            manif.pprint()
        else:
            fpt = MeFptTable(f, offset)
            fpt.pprint()
            if extract:
                fpt.extract(f, offset)
            dump_glut(f, offset, extract_huff)
            for p in fpt.parts:
                if not p.Offset in [0, 0xFFFFFFFF]:
                    dump_llut(f, offset, p.Offset, p.Name, extract_huff)
                if print_modmap and p.ptype() == PT_CODE:
                    poff = offset + p.Offset
                    manif = get_struct(f, poff, MeManifestHeader)
                    manif.parse_mods(f, poff)
                    if manif.Tag == '$MAN':
                        manif.PartitionName = p.Name
                    manifs.append(manif)

        if print_modmap:
            for manif in manifs:
                manif.print_mods()

        if off2 != -1:
            os.chdir("..")
