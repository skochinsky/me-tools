me_unpack.py
========

This script allows you to dump and extract Intel ME fimrware images. Supported formats:

 - Full SPI flash image with descriptor (signature 5A A5 F0 0F)
 - Full ME region image (signature '$FPT')
 - individual ME code partitions and update images (signature $MN2/$MAN)
 
Supported ME versions: 2.x - 9.x for desktop, 1.x-3.x for SpS, 1.x for TXE/SEC.

To unpack LZMA-compressed modules, the 'lzma' executable (from LZMA SDK) needs to be present next to the script;
otherwise modules are dumped as-is, with .lzma extension.

Huffman-compressed modules are not unpacked at the moment as the decompression dictionary is unknown.

Usage examples:

  me_util.py image.bin
  
  Quickly check if the image is recognized and dump some info about it.
  

  me_util.py image.bin -x
  
  Extract the ME paritions and modules from the image.
  

  me_util.py image.bin -x 12000
  
  Start parsing at offset 0x12000 in the file.   


  me_util.py image.bin -m
  
  Show the memory layout of the ME modules in memory


  me_util.py image.bin -h
  
  If Huffman-compressed modules are present, dump the individual compressed chunks, and create an image
  with uncompressed parts.
  

The script can be also used as a file loader for IDA; just drop it into the "loaders" directory (together with the
lzma executable). Only full ME region ($FPT) images are supported in this scenario.

me_util.py
========

This script allows you to send HECI (MEI) messages to the ME. The script currently runs only under Windows and
requires the ME drivers to be installed. You need to run it with admin privileges as it needs access to the driver.
