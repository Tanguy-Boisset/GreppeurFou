#!/usr/bin/python3

import base64
import argparse
import binascii

# Print colors
class col:
    HEADER = '\033[95m'
    INFO = '\033[94m'
    GOOD = '\033[96m'
    SUCCESS = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

print(f"""{col.INFO}
   ______                                              ______             
  / ____/_____ ___   ____   ____   ___   __  __ _____ / ____/____   __  __
 / / __ / ___// _ \ / __ \ / __ \ / _ \ / / / // ___// /_   / __ \ / / / /
/ /_/ // /   /  __// /_/ // /_/ //  __// /_/ // /   / __/  / /_/ // /_/ / 
\____//_/    \___// .___// .___/ \___/ \__,_//_/   /_/     \____/ \__,_/  
                 /_/    /_/                                               v0.1
                                                                          by Sopalinge
{col.ENDC}""")

description = "This tool will try to find flags using the usual CTF{xxxxx} format of many CTF challenges"

# Initialize parser
parser = argparse.ArgumentParser(description = description)

parser.add_argument("file", help = "file to inspect")
parser.add_argument("flag_header", help = "first few characters of the flag")

parser.add_argument("-v", "--verbose", help = "verbose output", action="store_true") # TODO
parser.add_argument("-r", "--recursive", help = "search recursively in a folder", action="store_true") # TODO
parser.add_argument("-p", "--password", help = "try different techniques with a password") # TODO
parser.add_argument("-d", "--delimiter", help = "delimiter for the flag (default : {})", default="{}")

args = parser.parse_args()

flag_start = args.flag_header + args.delimiter[0]
flag_end = args.delimiter[1]

def nonChangingChunk(flag, base):
    """
    Returns the chunk of baseXX that will not change depending on the content of the flag
    """
    if base == "base64":
        encoded = base64.b64encode(flag.encode()).decode('utf-8')
        if "=" in encoded:
            return encoded.replace('=', '')[:-1]
        else:
            return encoded
    elif base == "base32":
        encoded = base64.b32encode(flag.encode()).decode('utf-8')
        if "=" in encoded:
            return encoded.replace('=', '')[:-1]
        else:
            return encoded
    elif base == "base85":
        encoded = base64.b85encode(flag.encode()).decode('utf-8')
        return encoded[:-1]

print(f"{col.HEADER}[*] Pre-calculating all flag formats{col.ENDC}")
flag_format = {
    "cleartext" : flag_start,
    "ascii_space" : ' '.join(str(ord(char)) for char in flag_start),
    "ascii_colon" : ':'.join(str(ord(char)) for char in flag_start),
    "ascii_comma" : ','.join(str(ord(char)) for char in flag_start),
    "hex_none" : binascii.b2a_hex(flag_start.encode()).decode('utf-8'),
    "hex_space" : binascii.b2a_hex(flag_start.encode(), ' ').decode('utf-8'),
    "hex_0x" : ''.join([hex(ord(i)) for i in flag_start]),
    "hex_0x_space" : ' '.join([hex(ord(i)) for i in flag_start]),
    "hex_bsx" : '\\x'.join([str(hex(ord(i)))[2:4] for i in flag_start]),
    "hex_bsx_space" : ' \\x'.join([str(hex(ord(i)))[2:4] for i in flag_start]),
    "hex_colon" : binascii.b2a_hex(flag_start.encode(), ':').decode('utf-8'),
    "b64" : nonChangingChunk(flag_start, "base64"),
    "b32" : nonChangingChunk(flag_start, "base32"),
    "b85" : nonChangingChunk(flag_start, "base85"),
}

def extractFlag(line, flag, end_char):
    """
    Extract flag until end_char from string line
    """
    start = line.index(flag)
    if end_char == ' ':
        try:
            end = start + line[start:].index(' ')
        except ValueError:
            if line[len(line)-1] == '\n':
                end = len(line) - 1
            else:
                end = len(line)
    else:
        end = start + line[start:].index(end_char) + len(end_char)
    return line[start:end], start, end

def printSuccess(method, filename, line, line_number, decoded):
    """
    Print with colors the results of the search if successful
    """
    if decoded != "":
        print(f"""{col.SUCCESS}[+] FLAG FOUND in {method} in {col.ENDC}\
{col.SUCCESS}{col.UNDERLINE}{filename}{col.ENDC}{col.SUCCESS}, line {line_number}:{col.ENDC}\n\
    {line[max(0,start-20):start]}{col.GOOD}{col.BOLD}{flag}{col.ENDC}{line[end:min(len(line)-1,end+20)]}
    Decoded : {col.SUCCESS}{col.BOLD}{decoded}{col.ENDC}\n""")

    else:
        print(f"""{col.SUCCESS}[+] FLAG FOUND in {method} in {col.ENDC}\
{col.SUCCESS}{col.UNDERLINE}{filename}{col.ENDC}{col.SUCCESS}, line {line_number}:{col.ENDC}\n\
    {line[max(0,start-20):start]}{col.SUCCESS}{col.BOLD}{flag}{col.ENDC}{line[end:min(len(line)-1,end+20)]}\n""")

# Open file
print(f"{col.HEADER}[*] Looking for flags in {args.file}{col.ENDC}\n")

try:
    file = open(args.file, 'rb')
except FileNotFoundError:
    print("Could not find file %s..." % args.file)
    exit(1)

try:
    c = 0
    for line in file.readlines():
        c += 1

        line = line.decode('utf-8', errors='ignore')
        
        # Flag in cleartext ?
        check = flag_format["cleartext"]
        if check in line:
            flag, start, end = extractFlag(line, check, flag_end)
            printSuccess("CLEARTEXT", file.name, line, c, "")
        
        # Flag in ascii (separator : space) ?
        check = flag_format["ascii_space"]
        if check in line:
            flag, start, end = extractFlag(line, check, str(ord(flag_end)))
            printSuccess("ASCII", file.name, line, c, ''.join(chr(int(char)) for char in flag.split(' ')))
        
        # Flag in ascii (separator : colon) ?
        check = flag_format["ascii_colon"]
        if check in line:
            flag, start, end = extractFlag(line, check, str(ord(flag_end)))
            printSuccess("ASCII", file.name, line, c, ''.join(chr(int(char)) for char in flag.split(':')))
        
        # Flag in ascii (separator : comma) ?
        check = flag_format["ascii_comma"]
        if check in line:
            flag, start, end = extractFlag(line, check, str(ord(flag_end)))
            printSuccess("ASCII", file.name, line, c, ''.join(chr(int(char)) for char in flag.split(',')))
        
        # Flag in hex (separator : none) ?
        check = flag_format["hex_none"]
        if check in line:
            flag, start, end = extractFlag(line, check, binascii.b2a_hex(flag_end.encode()).decode('utf-8'))
            printSuccess("HEX", file.name, line, c, binascii.a2b_hex(flag).decode('utf-8'))
        
        # Flag in hex (separator : space) ?
        check = flag_format["hex_space"]
        if check in line:
            flag, start, end = extractFlag(line, check, binascii.b2a_hex(flag_end.encode(), ' ').decode('utf-8'))
            printSuccess("HEX", file.name, line, c, binascii.a2b_hex(flag.replace(' ', '')).decode('utf-8'))
        
        # Flag in hex (separator : 0x) ?
        check = flag_format["hex_0x"]
        if check in line:
            flag, start, end = extractFlag(line, check, ''.join([hex(ord(i)) for i in flag_end]))
            printSuccess("HEX", file.name, line, c, binascii.a2b_hex(flag.replace('0x', '')).decode('utf-8'))
        
        # Flag in hex (separator : 0x + space) ?
        check = flag_format["hex_0x_space"]
        if check in line:
            flag, start, end = extractFlag(line, check, ' '.join([hex(ord(i)) for i in flag_end]))
            printSuccess("HEX", file.name, line, c, binascii.a2b_hex(flag.replace(' 0x', '')).decode('utf-8'))
        
        # Flag in hex (separator : \x) ?
        check = flag_format["hex_bsx"]
        if check in line:
            flag, start, end = extractFlag(line, check, '\\x'.join([str(hex(ord(i)))[2:4] for i in flag_end]))
            printSuccess("HEX", file.name, line, c, binascii.a2b_hex(flag.replace('\\x', '')).decode('utf-8'))

        # Flag in hex (separator : \x + space) ?
        check = flag_format["hex_bsx_space"]
        if check in line:
            flag, start, end = extractFlag(line, check, ' \\x'.join([str(hex(ord(i)))[2:4] for i in flag_end]))
            printSuccess("HEX", file.name, line, c, binascii.a2b_hex(flag.replace(' \\x', '')).decode('utf-8'))
        
        # Flag in hex (separator : :) ?
        check = flag_format["hex_colon"]
        if check in line:
            flag, start, end = extractFlag(line, check, binascii.b2a_hex(flag_end.encode(), ':').decode('utf-8'))
            printSuccess("HEX", file.name, line, c, binascii.a2b_hex(flag.replace(':', '')).decode('utf-8'))
        
        # Flag in base64 ?
        check = flag_format["b64"]
        if check in line:
            flag, start, end = extractFlag(line, check, ' ')
            printSuccess("BASE64", file.name, line, c, base64.b64decode(flag).decode('utf-8'))
        
        # Flag in base32 ?
        check = flag_format["b32"]
        if check in line:
            flag, start, end = extractFlag(line, check, ' ')
            printSuccess("BASE32", file.name, line, c, base64.b32decode(flag).decode('utf-8'))
        
        # Flag in base85 ?
        check = flag_format["b85"]
        if check in line:
            flag, start, end = extractFlag(line, check, ' ')
            printSuccess("BASE85", file.name, line, c, base64.b85decode(flag).decode('utf-8'))

except KeyboardInterrupt:
    print("Exiting...")
    file.close()
    exit(0)