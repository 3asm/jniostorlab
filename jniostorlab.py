import sys
import re
import struct
from binascii import hexlify
import subprocess


DEBUG = False

def log(text):
    if DEBUG:
        print text

def found_method(method, addr, signature=''):
    print "[+] Found method '{}{}' at {}".format(method, signature, hex(addr))

def findall(pattern, text):
    result = []
    offset = text.find(pattern)
    while offset > -1:
        result.append(offset)
        offset = text.find(pattern, offset+1)
    return result

def get_text_symbols(filepath):

    result = []

    output = subprocess.check_output(['nm', '-D', '-C', '-g', filepath])
    for l in output.split('\n'):
        rr = re.match('([0-9a-f]+) ([a-zA-Z]{1}) (.*)', l)
        if rr:
            #print "==> {}".format(rr.group(0))
            result.append((rr.group(1), rr.group(2), rr.group(3)))

    return result

def parse_JNINativeMethod(offset, data):
    try:
        method_addr = struct.unpack('<i', co[offset:offset+4])[0]
        signature_addr = struct.unpack('<i', co[offset+4:offset+8])[0]
        method_body_addr = offset+8
        method = re.findall('^[^\x00-\x1F\x7F-\xFF]{1,}', data[method_addr:])[0]
        signature = re.findall('^[^\x00-\x1F\x7F-\xFF]{1,}', data[signature_addr:])[0]
        if method:
            log("======> method '{} {}' at {}".format(method, signature, hex(method_body_addr)))
            #find potentially missed in between methods
            return (method, method_body_addr, signature)
    except:
        pass


if __name__ == '__main__':

    filepath = sys.argv[1]

    symbols = get_text_symbols(filepath)
    #print symbols

    for s in symbols:

        if s[2].startswith('Java_'):
            log("======> method '{}' at {}".format(s[2], hex(int(s[0], 16))))
            found_method(s[2], int(s[0], 16))

        if 'JNI_OnLoad' in s[2]:
            methods_offsets = []
            with  open(filepath) as o:
                co = o.read()
                for m in re.finditer('\([a-zA-Z;/[$]*\)[a-zA-Z;/[$]+', co):
                    log("Found java signature pattern '{}' at {}".format(m.group(0), hex(m.start())))
                    addr = struct.pack('<i', m.start())

                    for po in findall(addr, co):
                        log("===> Found address pattern '{}' at {}".format(hexlify(addr), hex(po)))
                        offset = po-4
                        methods_offsets.append(offset)
                        parsed = parse_JNINativeMethod(offset, co)
                        if parsed:
                            found_method(*parsed)

            '''
            methods_offsets = sorted(list(set(methods_offsets)))
            o1 = methods_offsets[0]
            for o2 in methods_offsets[1:]:
                print o1, o2, o2-o1, parse_JNINativeMethod(o1, co)
                if (o2-o1)>12 and parse_JNINativeMethod(o1, co):
                    o3 = o1
                    while (o2-o3)>12:
                        o3 = o3+12
                        if parse_JNINativeMethod(o3, co):
                            print "guessing", o3, o2, o2-o3, parse_JNINativeMethod(o3, co)
                        else:
                            break


                o1 = o2
            '''

            #print methods_offsets