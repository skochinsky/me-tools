#!/usr/bin/env python

# based on http://lpaste.net/96724
# utility to send HECI(MEI) messages to Intel ME
# Copyright (c) 2012-2014 Igor Skochinsky
# Version 0.1 2014-10-19
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

import struct
import ctypes
import sys
from ctypes import POINTER, WinError, sizeof, byref
from ctypes.wintypes import DWORD, HANDLE, BOOL, WCHAR, LPCWSTR, HWND, ULONG

def ascii_char(c):
    if ord(c) >= 32 and ord(c) <= 126: return c
    return '.' 

def hex_dump(data, size= 16):	    
    def print_line(line, pad):
        bytes = map(ord, line)
        chars = map(ascii_char, line)
        bytestr = " ".join("%02X" % b for b in bytes) + "   "*pad
        print "%s | %s" % (bytestr, "".join(chars))
        pass

    for i in xrange(0, len(data)/size):
        data_line = data[i*size:i*size + size]
        print_line(data_line, 0)
        
    rem = len(data) % size
    if rem != 0:
        print_line(data[-rem:], size-rem)

NULL = None
HDEVINFO = ctypes.c_int
LPDWORD = PDWORD = ctypes.POINTER(DWORD)
ULONG_PTR = ctypes.POINTER(ULONG)
#~ PBYTE = ctypes.c_char_p
PBYTE = ctypes.c_void_p
PCWSTR = ctypes.wintypes.LPCWSTR
INVALID_HANDLE_VALUE = HANDLE(-1).value
UINT8  = ctypes.c_ubyte
UINT16 = ctypes.c_ushort
UINT32 = ctypes.c_uint

class GUID(ctypes.Structure):
    _fields_ = [
        ('Data1', ctypes.c_ulong),
        ('Data2', ctypes.c_ushort),
        ('Data3', ctypes.c_ushort),
        ('Data4', ctypes.c_ubyte*8),
    ]
    def __str__(self):
        return "{%08x-%04x-%04x-%s-%s}" % (
            self.Data1,
            self.Data2,
            self.Data3,
            ''.join(["%02x" % d for d in self.Data4[:2]]),
            ''.join(["%02x" % d for d in self.Data4[2:]]),
        )

class SP_DEVINFO_DATA(ctypes.Structure):
    _fields_ = [
        ('cbSize', DWORD),
        ('ClassGuid', GUID),
        ('DevInst', DWORD),
        ('Reserved', ULONG_PTR),
    ]
    def __str__(self):
        return "ClassGuid:%s DevInst:%s" % (self.ClassGuid, self.DevInst)
PSP_DEVINFO_DATA = ctypes.POINTER(SP_DEVINFO_DATA)

class SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
    _fields_ = [
        ('cbSize', DWORD),
        ('InterfaceClassGuid', GUID),
        ('Flags', DWORD),
        ('Reserved', ULONG_PTR),
    ]
    def __str__(self):
        return "InterfaceClassGuid:%s Flags:%s" % (self.InterfaceClassGuid, self.Flags)

PSP_DEVICE_INTERFACE_DATA = ctypes.POINTER(SP_DEVICE_INTERFACE_DATA)

PSP_DEVICE_INTERFACE_DETAIL_DATA = ctypes.c_void_p

class dummy(ctypes.Structure):
    _fields_=[("d1", DWORD), ("d2", WCHAR)]
    _pack_ = 1
SIZEOF_SP_DEVICE_INTERFACE_DETAIL_DATA_W = ctypes.sizeof(dummy)

class _US(ctypes.Structure):
    _fields_ = [
        ("Offset",          DWORD),
        ("OffsetHigh",      DWORD),
    ]

class _U(ctypes.Union):
    _fields_ = [
        ("s",               _US),
        ("Pointer",         ctypes.c_void_p),
    ]

    _anonymous_ = ("s",)

class OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal",        POINTER(ULONG)),
        ("InternalHigh",    POINTER(ULONG)),

        ("u",               _U),

        ("hEvent",          HANDLE),
    ]
    _anonymous_ = ("u",)

SetupDiDestroyDeviceInfoList = ctypes.windll.setupapi.SetupDiDestroyDeviceInfoList
SetupDiDestroyDeviceInfoList.argtypes = [HDEVINFO]
SetupDiDestroyDeviceInfoList.restype = BOOL

SetupDiGetClassDevs = ctypes.windll.setupapi.SetupDiGetClassDevsW
SetupDiGetClassDevs.argtypes = [ctypes.POINTER(GUID), PCWSTR, HWND, DWORD]
SetupDiGetClassDevs.restype = HDEVINFO

SetupDiEnumDeviceInterfaces = ctypes.windll.setupapi.SetupDiEnumDeviceInterfaces
SetupDiEnumDeviceInterfaces.argtypes = [HDEVINFO, PSP_DEVINFO_DATA, ctypes.POINTER(GUID), DWORD, PSP_DEVICE_INTERFACE_DATA]
SetupDiEnumDeviceInterfaces.restype = BOOL

SetupDiGetDeviceInterfaceDetail = ctypes.windll.setupapi.SetupDiGetDeviceInterfaceDetailW
SetupDiGetDeviceInterfaceDetail.argtypes = [HDEVINFO, PSP_DEVICE_INTERFACE_DATA, PSP_DEVICE_INTERFACE_DETAIL_DATA, DWORD, PDWORD, PSP_DEVINFO_DATA]
SetupDiGetDeviceInterfaceDetail.restype = BOOL

SetupDiGetDeviceRegistryProperty = ctypes.windll.setupapi.SetupDiGetDeviceRegistryPropertyW
SetupDiGetDeviceRegistryProperty.argtypes = [HDEVINFO, PSP_DEVINFO_DATA, DWORD, PDWORD, PBYTE, DWORD, PDWORD]
SetupDiGetDeviceRegistryProperty.restype = BOOL


DIGCF_PRESENT = 2
DIGCF_DEVICEINTERFACE = 16
ERROR_INSUFFICIENT_BUFFER = 122
SPDRP_HARDWAREID = 1
SPDRP_FRIENDLYNAME = 12
SPDRP_LOCATION_INFORMATION = 13
ERROR_NO_MORE_ITEMS = 259
GENERIC_READ  = 0x80000000
GENERIC_WRITE = 0x40000000

FILE_SHARE_READ   = 0x00000001
FILE_SHARE_WRITE  = 0x00000002
FILE_SHARE_DELETE = 0x00000004

OPEN_EXISTING = 3


CreateFile = ctypes.windll.kernel32.CreateFileW
CreateFile.argtypes = [ctypes.c_wchar_p, DWORD, DWORD, ctypes.c_void_p,
                       DWORD, DWORD, HANDLE]
CreateFile.restype = HANDLE

DeviceIoControl = ctypes.windll.kernel32.DeviceIoControl
DeviceIoControl.argtypes = [HANDLE, DWORD, ctypes.c_void_p, DWORD,
                            ctypes.c_void_p, DWORD, LPDWORD, ctypes.c_void_p]
DeviceIoControl.restype = BOOL

CloseHandle = ctypes.windll.kernel32.CloseHandle
CloseHandle.argtypes = [HANDLE]
CloseHandle.restype = BOOL

ReadFile = ctypes.windll.kernel32.ReadFile
ReadFile.argtypes = (HANDLE, ctypes.c_void_p, DWORD, POINTER(DWORD), POINTER(OVERLAPPED))
ReadFile.restype = BOOL

WriteFile = ctypes.windll.kernel32.WriteFile
WriteFile.argtypes = (HANDLE, ctypes.c_void_p, DWORD, POINTER(DWORD), POINTER(OVERLAPPED))
WriteFile.restype = BOOL

GUID_DEVINTERFACE_HECI = GUID(0xE2D1FF34, 0x3458, 0x49A9, (ctypes.c_ubyte*8)(0x88, 0xDA, 0x8E, 0x69, 0x15, 0xCE, 0x9B, 0xE5))
MKHI_SUBSYSTEM_GUID    = GUID(0x8E6A6715, 0x9ABC, 0x4043, (ctypes.c_ubyte*8)(0x88, 0xEF, 0x9E, 0x39, 0xC6, 0xF6, 0x3E, 0x0F))

def CTL_CODE(DeviceType, Function, Method, Access):
  return (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))

FILE_DEVICE_HECI = 0x8000
METHOD_BUFFERED = 0
FILE_READ_ACCESS  = 1
FILE_WRITE_ACCESS  = 2

IOCTL_HECI_GET_VERSION    = CTL_CODE(FILE_DEVICE_HECI, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS|FILE_WRITE_ACCESS)
IOCTL_HECI_CONNECT_CLIENT = CTL_CODE(FILE_DEVICE_HECI, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS|FILE_WRITE_ACCESS)
IOCTL_HECI_WD             = CTL_CODE(FILE_DEVICE_HECI, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS|FILE_WRITE_ACCESS)

def get_heci_dev_path():
    g_hdi = SetupDiGetClassDevs(ctypes.byref(GUID_DEVINTERFACE_HECI), None, NULL, DIGCF_DEVICEINTERFACE|DIGCF_PRESENT);
    if g_hdi != INVALID_HANDLE_VALUE:
        try:
            did = SP_DEVICE_INTERFACE_DATA()
            did.cbSize = ctypes.sizeof(did)
            res = SetupDiEnumDeviceInterfaces(
                    g_hdi,
                    None,
                    ctypes.byref(GUID_DEVINTERFACE_HECI),
                    0,
                    ctypes.byref(did))
            if res == 0:
                if ctypes.GetLastError() == ERROR_NO_MORE_ITEMS:
                    return None
                raise ctypes.WinError()
            dwNeeded = DWORD()
            # get the size
            res = SetupDiGetDeviceInterfaceDetail(
                g_hdi,
                ctypes.byref(did),
                None, 0, ctypes.byref(dwNeeded),
                None)
            if res == 0 and ctypes.GetLastError() != ERROR_INSUFFICIENT_BUFFER:
                raise ctypes.WinError()

            class SP_DEVICE_INTERFACE_DETAIL_DATA_A(ctypes.Structure):
                    _fields_ = [
                        ('cbSize', DWORD),
                        ('DevicePath', WCHAR*(dwNeeded.value - ctypes.sizeof(DWORD))),
                    ]
                    def __str__(self):
                        return "DevicePath:%s" % (self.DevicePath,)

            idd = SP_DEVICE_INTERFACE_DETAIL_DATA_A()
            idd.cbSize = SIZEOF_SP_DEVICE_INTERFACE_DETAIL_DATA_W
            res = SetupDiGetDeviceInterfaceDetail(
                g_hdi,
                ctypes.byref(did),
                ctypes.byref(idd), dwNeeded, None, None)
            if res == 0:
                raise ctypes.WinError()
            return idd.DevicePath
        finally:
            SetupDiDestroyDeviceInfoList(g_hdi)

class HeciError(Exception):
    pass

class HECI_VERSION(ctypes.Structure):
    _fields_=[
      ("major",  UINT8),
      ("minor",  UINT8),
      ("hotfix", UINT8),
      ("build",  UINT16),
    ]
    _pack_ = 1
    def __str__(self):
        return "%d.%d.%d.%d" % (
            self.major,
            self.minor,
            self.hotfix,
            self.build,
        )

class HECI_CLIENT(ctypes.Structure):
    _fields_=[
      ("MaxMessageLength", UINT32),
      ("ProtocolVersion", UINT8),
    ]
    _pack_ = 1
    def __str__(self):
        return "Max msg len = 0x%X, protocol ver = %d" % (
            self.MaxMessageLength,
            self.ProtocolVersion,
        )

class HeciWin32:
    def __init__(self, guid):
        self._handle = INVALID_HANDLE_VALUE
        devpath = get_heci_dev_path()
        if not devpath:
            raise HeciError("HECI interface not present")
        print "Opening HECI device %s" % devpath
        self._handle = CreateFile(devpath, GENERIC_WRITE|GENERIC_READ, FILE_SHARE_WRITE|FILE_SHARE_READ, None, OPEN_EXISTING, 0, None)
        if self._handle == INVALID_HANDLE_VALUE:
            print "Error opening HECI interface"
            raise ctypes.WinError()
        heciver = self._doIoctl(IOCTL_HECI_GET_VERSION, None, HECI_VERSION)
        print "Driver version: %s" % heciver
        clinfo = self._doIoctl(IOCTL_HECI_CONNECT_CLIENT, guid, HECI_CLIENT)
        print "connected to %s: %s" % (guid, clinfo)
        self.maxbufsize = clinfo.MaxMessageLength
    
    def _doIoctl(self, code, inbuf, outtype):
        if inbuf is None:
            inlen = 0
            inptr = NULL
        else:
            inlen = ctypes.sizeof(inbuf)
            inptr = ctypes.addressof(inbuf)
        outbuf = outtype()
        outlen = ctypes.sizeof(outbuf)
        BytesReturned = DWORD(0)
        res = DeviceIoControl(self._handle, code, inptr, inlen, ctypes.addressof(outbuf), outlen, ctypes.byref(BytesReturned), NULL)
        if res == 0:
            print "DeviceIoControl error"
            raise ctypes.WinError()
        return outbuf
    
    def _sendMessage(self, inbuf):
        inlen = ctypes.sizeof(inbuf)
        inptr = ctypes.addressof(inbuf)
        bytesWritten = DWORD(0)
        res = WriteFile(self._handle, inptr, inlen, ctypes.byref(bytesWritten), NULL)
        if res == 0:
            print "WriteFile error 1"
            raise ctypes.WinError()
        if bytesWritten.value != inlen:
            print "WriteFile error 2 (written: %d, inlen: %d)" % (bytesWritten.value, inlen)
            raise ctypes.WinError()

    def _getMessage(self, outtype):
        outlen = self.maxbufsize
        outbuf = ctypes.create_string_buffer(outlen)
        bytesRead = DWORD(0)
        res = ReadFile(self._handle, ctypes.byref(outbuf), outlen, ctypes.byref(bytesRead), NULL)
        if res == 0:
            print "ReadFile error 1"
            raise ctypes.WinError()
        retval = outtype()
        rvlen  = ctypes.sizeof(retval)
        if bytesRead.value != rvlen:
            print "warning: (got %d bytes, expected %d)" % (bytesRead.value, rvlen)
            hex_dump(outbuf.raw[:bytesRead.value])
        ctypes.memmove(ctypes.addressof(retval), ctypes.addressof(outbuf), min(bytesRead.value, rvlen))
        return retval

    def _call(self, inbuf, outbuf):
        self._sendMessage(inbuf)
        return self._getMessage(outbuf)

    def __del__(self):
        if self._handle != INVALID_HANDLE_VALUE:
            CloseHandle(self._handle)
        self._handle = INVALID_HANDLE_VALUE

MKHI_CBM_GROUP_ID     = 0
MKHI_PM_GROUP_ID      = 1
MKHI_PWD_GROUP_ID     = 2
MKHI_FWCAPS_GROUP_ID  = 3
MKHI_APP_GROUP_ID     = 4
MKHI_SPI_GROUP_ID     = 5
MKHI_MDES_GROUP_ID    = 8
MKHI_NM_GROUP_ID      = 0x11
MKHI_GEN_GROUP_ID     = 0xFF

GEN_GET_MKHI_VERSION_CMD    	= 0x01 
GEN_GET_MKHI_VERSION_CMD_ACK	= 0x81 
GEN_GET_FW_VERSION_CMD			= 0x02 
GEN_GET_FW_VERSION_CMD_ACK		= 0x82 
GEN_UNCFG_WO_PWD_CMD			= 0x0D 
GEN_UNCFG_WO_PWD_CMD_ACK		= 0x8D 

class MKHI_MESSAGE_HEADER(ctypes.Structure):
    _fields_ = [
        ("GroupId",    UINT32, 8),
        ("Command",    UINT32, 7),
        ("IsResponse", UINT32, 1),
        ("Reserved",   UINT32, 8),
        ("Result",     UINT32, 8),
    ]
    def __init__(self, grp = 0, cmd = 0):
        self.GroupId = grp
        self.Command = cmd
        self.IsResponse = self.Reserved = self.Result = 0

    def __str__(self):
        return "group %02X cmd %02X response %d result %02X" % (
          self.GroupId,
          self.Command,
          self.IsResponse,
          self.Result,
        )

class GEN_GET_MKHI_VERSION(ctypes.Structure):
    _fields_ = [
        ("Header",    MKHI_MESSAGE_HEADER),
    ]
    def __init__(self):
        self.Header.__init__(MKHI_GEN_GROUP_ID, GEN_GET_MKHI_VERSION_CMD)
    def __str__(self):
        return self.Header.__str__()

class GEN_GET_MKHI_VERSION_ACK(ctypes.Structure):
    _fields_ = [
        ("Header",    MKHI_MESSAGE_HEADER),
        ("Minor",     UINT32, 16),
        ("Major",     UINT32, 16),
    ]
    def __str__(self):
        return "header [%s] version [%d.%d]" % (
          self.Header,
          self.Major,
          self.Minor,
        )
        
class FW_VERSION(ctypes.Structure):
    _fields_ = [
        ("CodeMinor",   UINT32, 16),
        ("CodeMajor",   UINT32, 16),
        ("CodeBuildNo", UINT32, 16),
        ("CodeHotFix",  UINT32, 16),
        ("RcvyMinor",   UINT32, 16),
        ("RcvyMajor",   UINT32, 16),
        ("RcvyBuildNo", UINT32, 16),
        ("RcvyHotFix",  UINT32, 16),
        ("BackMinor",   UINT32, 16),
        ("BackMajor",   UINT32, 16),
        ("BackBuildNo", UINT32, 16),
        ("BackHotFix",  UINT32, 16),
    ]
    def __str__(self):
        return "code %d.%d.%d.%d rcvy %d.%d.%d.%d back? %d.%d.%d.%d" % (
          self.CodeMajor,
          self.CodeMinor,
          self.CodeHotFix,
          self.CodeBuildNo,
          self.RcvyMajor,
          self.RcvyMinor,
          self.RcvyHotFix,
          self.RcvyBuildNo,
          self.BackMajor,
          self.BackMinor,
          self.BackHotFix,
          self.BackBuildNo,
        )

class GEN_GET_FW_VER(ctypes.Structure):
    _fields_ = [
        ("Header",  MKHI_MESSAGE_HEADER),
    ]
    def __init__(self):
        self.Header.__init__(MKHI_GEN_GROUP_ID, GEN_GET_FW_VERSION_CMD)
    def __str__(self):
        return self.Header.__str__()

class GEN_GET_FW_VER_ACK(ctypes.Structure):
    _fields_ = [
        ("Header",    MKHI_MESSAGE_HEADER),
        ("Data",      FW_VERSION),
    ]
    def __str__(self):
        return "header [%s] data [%s]" % (
          self.Header,
          self.Data,
        )        

def buf0():
    return ctypes.create_string_buffer(0)

heci_mkhi = HeciWin32(MKHI_SUBSYSTEM_GUID)
msg = GEN_GET_MKHI_VERSION()
print "Sending GEN_GET_MKHI_VERSION [%s]" % msg
heciver = heci_mkhi._call(msg, GEN_GET_MKHI_VERSION_ACK)
print "MKHI protocol version: %s" % heciver

msg = GEN_GET_FW_VER()
print "Sending GEN_GET_FW_VER [%s]" % msg
heciver = heci_mkhi._call(msg, GEN_GET_FW_VER_ACK)
print "Firmware version: %s" % heciver

if len(sys.argv) < 3:
    for i in range(0x20):
        if i in [0, 3, 5, 0xa, 0x12]: continue
        msg = MKHI_MESSAGE_HEADER(MKHI_GEN_GROUP_ID, i)
        print "Sending GEN message %02X: %s" % (i, msg)
        # if i in [0, 0xb, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14]: continue
        # msg = MKHI_MESSAGE_HEADER(MKHI_MDES_GROUP_ID, i)
        # print "Sending MDES message %02X: %s" % (i, msg)
        reply = heci_mkhi._call(msg, MKHI_MESSAGE_HEADER)
        print "  >>> reply: %s" % reply

else:
    # meutil.py <group> <cmd> <payload>
    group = int(sys.argv[1], 16)
    cmd   = int(sys.argv[2], 16)
    payload = "".join(sys.argv[3:]).replace(" ","").decode('hex')
    
    class MKHI_MSG_ANY(ctypes.Structure):
        _fields_ = [
            ("Header",  MKHI_MESSAGE_HEADER),
            ("Data",    UINT8*len(payload)),
        ]
        _pack_ = 1
        def __init__(self):
            self.Header.__init__(group, cmd)
            self.Data.__init__(*bytearray(payload))
        def __str__(self):
            return "size %d header [%s] data [%s]" % (
              ctypes.sizeof(self),
              self.Header,
              " ".join("%02X"%b for b in self.Data),
            )        

    msg = MKHI_MSG_ANY()
    print "Sending message: %s" % (msg)
    reply = heci_mkhi._call(msg, MKHI_MESSAGE_HEADER)
    print "  >>> reply: %s" % reply


"""
# source: http://lpaste.net/96724

libc = cdll.LoadLibrary('libc.so.6')
ioctl = libc.ioctl
ioctl.argtypes = (c_int, c_int, c_char_p)
ioctl.restype = c_int

IOCTL_MEI_CONNECT_CLIENT = 0xc0104801 # _IOWR('H' , 0x01, struct mei_connect_client_data)

def connect(fd, uustr) :
    u = uuid.UUID(uustr)
    b = c_buffer(u.get_bytes_le())
    #print 'uuid', b.raw.encode('hex')
    if ioctl(fd, IOCTL_MEI_CONNECT_CLIENT, b) == -1 :
        raise Error("ioctl error")
    maxlen,vers = struct.unpack("<IB", b.raw[:5])
    #print "result buffer %r" % (b.raw.encode('hex'))
    return maxlen, vers

FWU_GET_VERSION = 0
FWU_GET_INFO = 8

def fwupdate_getVer(fd, maxlen) :
    cmd = struct.pack("<I", FWU_GET_VERSION)
    os.write(fd, cmd)
    buf = os.read(fd, maxlen)
    print "len %x" % len(buf)
    print hexdump(buf)

    # this is obviously not lined up right! but this is what the
    # headers I have say..  would be good to compare correct values
    # taken from bios screen 
    ty,st,sku,ich,mch,vend,updst,hwsku,ca,cb,cc,cd,da,db,dc,dd = struct.unpack("<IIIIIIII4H4H", buf)
    if ty != FWU_GET_VERSION+1 :
        raise Error("bad response type %x" % ty)
    print "ty %x status %x sku %x ich %x mch %x vendor %x" % (ty,st,sku,ich,mch,vend)
    print "hwsku %x code %x.%x.%x.%x amt %x.%x.%x.%x" % (hwsku, ca,cb,cc,cd, da,db,dc,dd)
    # assert vend == 0x8086 # !!!

def getBits(x, *bs) :
    rs = []
    for b in bs :
        rs.append(x & ((1<<b)-1))
        x >>= b
    return rs

def fwupdate_getInfo(fd, maxlen) :
    cmd = struct.pack("<I", FWU_GET_INFO)
    os.write(fd, cmd)
    buf = os.read(fd, maxlen)
    ty,st,a,b,c,d,pol,mode,boot,bits,ver = struct.unpack("<II4HIIII20s", buf)

    fuse,flashprot,fwover,mereset,fwovercnt,resv = getBits(bits, 1, 1, 2, 2, 8, 18)
    ver = ver.rstrip('\0')
    if ty != FWU_GET_INFO+1 :
        raise Error("bad response type %x" % ty)

    #print hexdump(buf)
    print "type %x status %x meb %x.%x.%x.%x flashpolicy %x managemode %x bootstat %x bits %x name %r" % (ty,st,a,b,c,d,pol,mode,boot,bits,ver)
    print "bits: cryptofuse %x" % fuse
    print "      flashprotect %x" % flashprot
    print "      fwoverridequalifier %x" % fwover
    print "      meresetreason %x" % mereset
    print "      fwoverwritecounter %x" % fwovercnt
    print "      reserved %x" % resv


fd = os.open("/dev/mei", os.O_RDWR)
fwupdate = '309dcde8-ccb1-4062-8f78-600115a34327'
maxlen,vers = connect(fd, fwupdate)
print "connected - maxlen %x vers %x" % (maxlen, vers)

print fwupdate_getVer(fd, maxlen)
print fwupdate_getInfo(fd, maxlen)

"""