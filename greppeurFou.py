#!/usr/bin/python3

import base64
import argparse
import binascii
import os
import urllib.parse as url
import codecs
import re
from prettytable import PrettyTable

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
                 /_/    /_/                                               v0.4
                                                                          by Sopalinge
{col.ENDC}""")

description = "This tool will try to find flags using the usual CTF{xxxxx} format of many CTF challenges"

# Initialize parser
parser = argparse.ArgumentParser(description = description)

parser.add_argument("file", help = "file to inspect")
parser.add_argument("flag_header", help = "first few characters of the flag")

parser.add_argument("-v", "--verbose", help = "verbose output", action="store_true")
parser.add_argument("-r", "--recursive", help = "search recursively in a folder", action="store_true")
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
    if base == "base64_url":
        encoded = base64.urlsafe_b64encode(flag.encode()).decode('utf-8')
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

print(f"{col.HEADER}[*] Pre-calculating all flag formats and compiling regex{col.ENDC}")
flag_format = {
    "cleartext" : flag_start,
    "url" : url.quote(flag_start),
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
    "b64_url" : nonChangingChunk(flag_start, "base64_url"),
    "b32" : nonChangingChunk(flag_start, "base32"),
    "b85" : nonChangingChunk(flag_start, "base85"),
    "utf-16" : flag_start,
    "rot13" : codecs.encode(flag_start, 'rot_13')
}
                            
regex_dict = {
    "ipv4" : {
        "regex" : re.compile(r"(?:^|\b(?<!\.))(?:1?\d?\d|2[0-4]\d|25[0-5])(?:\.(?:1?\d?\d|2[0-4]\d|25[0-5])){3}(?=$|[^\w.])"),
        "rslt" : {
            #"example_ip" : {
            #    "file1" : [12, 1367, 10983],
            #    "file2" : [2],
            #},
        },
    },
    "url" : {
        "regex" : re.compile(r'(((http|https|ftp)|mailto)[.:][^ >"\t]*|www\.[-a-z0-9.]+)'),
        "rslt" : {},
    },
    "email" : {
        "regex" : re.compile(r'\b[a-zA-Z0-9.#?$*_-]+@[a-zA-Z0-9.#?$*_-]+\.[a-zA-Z0-9.-]+\b'),
        "rslt" : {},
    },
}

def parseRegexRslt(rslt, name, filename, line_number):
    for r in rslt:
        try:
            regex_dict[name]["rslt"][r][filename].append(line_number)
        except KeyError:
            try:
                regex_dict[name]["rslt"][r][filename] = [line_number]
            except:
                regex_dict[name]["rslt"][r] = {filename: [line_number]}

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
    if decoded != "" and decoded != "ERROR":
        print(f"""{col.SUCCESS}[+] FLAG FOUND in {method} in {col.ENDC}\
{col.SUCCESS}{col.UNDERLINE}{filename}{col.ENDC}{col.SUCCESS}, line {line_number}:{col.ENDC}\n\
    {line[max(0,start-20):start]}{col.GOOD}{col.BOLD}{flag}{col.ENDC}{line[end:min(len(line)-1,end+20)]}
    Decoded : {col.SUCCESS}{col.BOLD}{decoded}{col.ENDC}\n""")

    elif decoded == "":
        print(f"""{col.SUCCESS}[+] FLAG FOUND in {method} in {col.ENDC}\
{col.SUCCESS}{col.UNDERLINE}{filename}{col.ENDC}{col.SUCCESS}, line {line_number}:{col.ENDC}\n\
    {line[max(0,start-20):start]}{col.SUCCESS}{col.BOLD}{flag}{col.ENDC}{line[end:min(len(line)-1,end+20)]}\n""")
    
    else:
        print(f"""{col.SUCCESS}[+] FLAG FOUND in {method} in {col.ENDC}\
{col.SUCCESS}{col.UNDERLINE}{filename}{col.ENDC}{col.SUCCESS}, line {line_number}:{col.ENDC}\n\
    {line[max(0,start-20):start]}{col.SUCCESS}{col.BOLD}{flag}{col.ENDC}{line[end:min(len(line)-1,end+20)]}\n
    {col.WARNING}[-] Unable to decode flag automatically - sorry, you're on your own for this part :({col.ENDC}\n""")

# Build all files to check recursively
if args.recursive:
    paths = []
    root_folder = args.file
    if root_folder[-1] == "/":
        root_folder = root_folder[:-1]
    if not os.path.isdir(root_folder):
        print(f"{col.FAIL}[-] Option --recursive was used but {args.file} is not a folder or does not exist{col.ENDC}\n")
        exit(1)
    for root, dirs, files in os.walk(root_folder):
        for file in files:
            paths.append(root + '/' + file)
else:
    if not os.path.isfile(args.file):
        print(f"{col.FAIL}[-] {args.file} is not a file or does not exist. Use -r for a recursive search in a folder{col.ENDC}\n")
        exit(1)
    paths = [args.file]

for filename in paths:
    if args.verbose:
        print(f"{col.HEADER}[*] Looking for flags in {filename}{col.ENDC}\n")
    try:
        file = open(filename, 'rb')
    except FileNotFoundError:
        print(f"{col.FAIL}[-] Could not find file {filename}...{col.ENDC}\n")
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
            
            # Flag URL encoded ?
            check = flag_format["url"]
            if check in line:
                flag, start, end = extractFlag(line, check, url.quote(flag_end))
                try:
                    decoded = url.unquote(flag)
                except:
                    decoded = "ERROR"
                printSuccess("URL ENCODED", file.name, line, c, decoded)
            
            # Flag in ascii (separator : space) ?
            check = flag_format["ascii_space"]
            if check in line:
                flag, start, end = extractFlag(line, check, str(ord(flag_end)))
                try:
                    decoded = ''.join(chr(int(char)) for char in flag.split(' '))
                except:
                    decoded = "ERROR"
                printSuccess("ASCII", file.name, line, c, decoded)
            
            # Flag in ascii (separator : colon) ?
            check = flag_format["ascii_colon"]
            if check in line:
                flag, start, end = extractFlag(line, check, str(ord(flag_end)))
                try:
                    decoded = ''.join(chr(int(char)) for char in flag.split(':'))
                except:
                    decoded = "ERROR"
                printSuccess("ASCII", file.name, line, c, decoded)
            
            # Flag in ascii (separator : comma) ?
            check = flag_format["ascii_comma"]
            if check in line:
                flag, start, end = extractFlag(line, check, str(ord(flag_end)))
                try:
                    decoded = ''.join(chr(int(char)) for char in flag.split(','))
                except:
                    decoded = "ERROR"
                printSuccess("ASCII", file.name, line, c, decoded)
            
            # Flag in hex (separator : none) ?
            check = flag_format["hex_none"]
            if check in line:
                flag, start, end = extractFlag(line, check, binascii.b2a_hex(flag_end.encode()).decode('utf-8', errors='ignore'))
                try:
                    decoded = binascii.a2b_hex(flag).decode('utf-8', errors='ignore')
                except:
                    decoded = "ERROR"
                printSuccess("HEX", file.name, line, c, decoded)
            
            # Flag in hex (separator : space) ?
            check = flag_format["hex_space"]
            if check in line:
                flag, start, end = extractFlag(line, check, binascii.b2a_hex(flag_end.encode(), ' ').decode('utf-8', errors='ignore'))
                try:
                    decoded = binascii.a2b_hex(flag.replace(' ', '')).decode('utf-8', errors='ignore')
                except:
                    decoded = "ERROR"
                printSuccess("HEX", file.name, line, c, decoded)
            
            # Flag in hex (separator : 0x) ?
            check = flag_format["hex_0x"]
            if check in line:
                flag, start, end = extractFlag(line, check, ''.join([hex(ord(i)) for i in flag_end]))
                try:
                    decoded = binascii.a2b_hex(flag.replace('0x', '')).decode('utf-8', errors='ignore')
                except:
                    decoded = "ERROR"
                printSuccess("HEX", file.name, line, c, decoded)
            
            # Flag in hex (separator : 0x + space) ?
            check = flag_format["hex_0x_space"]
            if check in line:
                flag, start, end = extractFlag(line, check, ' '.join([hex(ord(i)) for i in flag_end]))
                try:
                    decoded = binascii.a2b_hex(flag.replace(' 0x', '')).decode('utf-8', errors='ignore')
                except:
                    decoded = "ERROR"
                printSuccess("HEX", file.name, line, c, decoded)
            
            # Flag in hex (separator : \x) ?
            check = flag_format["hex_bsx"]
            if check in line:
                flag, start, end = extractFlag(line, check, '\\x'.join([str(hex(ord(i)))[2:4] for i in flag_end]))
                try:
                    decoded = binascii.a2b_hex(flag.replace('\\x', '')).decode('utf-8', errors='ignore')
                except:
                    decoded = "ERROR"
                printSuccess("HEX", file.name, line, c, decoded)

            # Flag in hex (separator : \x + space) ?
            check = flag_format["hex_bsx_space"]
            if check in line:
                flag, start, end = extractFlag(line, check, ' \\x'.join([str(hex(ord(i)))[2:4] for i in flag_end]))
                try:
                    decoded = binascii.a2b_hex(flag.replace(' \\x', '')).decode('utf-8', errors='ignore')
                except:
                    decoded = "ERROR"
                printSuccess("HEX", file.name, line, c, decoded)
            
            # Flag in hex (separator : :) ?
            check = flag_format["hex_colon"]
            if check in line:
                flag, start, end = extractFlag(line, check, binascii.b2a_hex(flag_end.encode(), ':').decode('utf-8', errors='ignore'))
                try:
                    decoded = binascii.a2b_hex(flag.replace(':', '')).decode('utf-8', errors='ignore')
                except:
                    decoded = "ERROR"
                printSuccess("HEX", file.name, line, c, decoded)
            
            # Flag in base64 ?
            check = flag_format["b64"]
            if check in line:
                flag, start, end = extractFlag(line, check, ' ')
                try:
                    decoded = base64.b64decode(flag+"==").decode('utf-8', errors='ignore')
                except:
                    decoded = "ERROR"
                printSuccess("BASE64", file.name, line, c, decoded)
            
            # Flag in base64 (URL proof) ?
            check = flag_format["b64_url"]
            if check in line:
                flag, start, end = extractFlag(line, check, ' ')
                try:
                    decoded = base64.urlsafe_b64decode(flag+"==").decode('utf-8', errors='ignore')
                except:
                    decoded = "ERROR"
                printSuccess("BASE64", file.name, line, c, decoded)
            
            # Flag in base32 ?
            check = flag_format["b32"]
            if check in line:
                flag, start, end = extractFlag(line, check, ' ')
                try:
                    decoded = base64.b32decode(flag).decode('utf-8', errors='ignore')
                except:
                    decoded = "ERROR"
                printSuccess("BASE32", file.name, line, c, decoded)
            
            # Flag in base85 ?
            check = flag_format["b85"]
            if check in line:
                flag, start, end = extractFlag(line, check, ' ')
                try:
                    decoded = base64.b85decode(flag).decode('utf-8', errors='ignore')
                except:
                    decoded = "ERROR"
                printSuccess("BASE85", file.name, line, c, decoded)

            # Flag in UTF-16 ?
            check = flag_format["utf-16"]
            if check in line.encode().decode('utf-16', errors='ignore'):
                flag, start, end = extractFlag(line.encode().decode('utf-16', errors='ignore'), check, flag_end)
                try:
                    decoded = flag
                except:
                    decoded = "ERROR"
                printSuccess("UTF-16", file.name, line, c, decoded)

            # Flag in ROT13 ?
            check = flag_format["rot13"]
            if check in line:
                flag, start, end = extractFlag(line, check, codecs.encode(flag_end, 'rot_13'))
                try:
                    decoded = codecs.encode(flag, 'rot_13')
                except:
                    decoded = "ERROR"
                printSuccess("ROT13", file.name, line, c, decoded)
            
            ## Information gathering
            # IPv4 Addresses
            ipv4 = re.findall(regex_dict["ipv4"]["regex"], line)
            parseRegexRslt(ipv4, "ipv4", file.name, c)

            # URL
            url_tmp = re.findall(regex_dict["url"]["regex"], line)
            url_r = []
            for r in url_tmp:
                url_r.append(r[0])
            parseRegexRslt(url_r, "url", file.name, c)

            # Email addresses
            email = re.findall(regex_dict["email"]["regex"], line)
            parseRegexRslt(email, "email", file.name, c)
                

    except KeyboardInterrupt:
        print(f"\n{col.WARNING}CTRL-C pressed. Exiting.{col.ENDC}\n")
        file.close()
        exit(0)

    file.close()

## Tables from information gathering
# TODO : truncate long tables
# TODO : ask to store data in csv
network_table = PrettyTable([])
credz_table = PrettyTable([])
hash_table = PrettyTable([])

# Network table
net_ipv4 = list(regex_dict["ipv4"]["rslt"].keys())
net_url = list(regex_dict["url"]["rslt"].keys())

row_nb_network = max(len(net_ipv4), len(net_url))

network_table.add_column("IPv4 addresses", net_ipv4 + [''] * (row_nb_network - len(net_ipv4)))
network_table.add_column("URL", net_url + [''] * (row_nb_network - len(net_url)))

# Credz table
credz_email = list(regex_dict["email"]["rslt"].keys())

row_nb_credz = max(len(email), 0)

credz_table.add_column("Email addresses", credz_email + [''] * (row_nb_credz - len(credz_email)))

# Print tables
print(f"{col.HEADER}Information gathered across all files :{col.ENDC}")
print(f"{col.INFO}Network{col.ENDC}")
print(network_table)
print(f"\n{col.INFO}Credentials{col.ENDC}")
print(credz_table)
#print(hash_table)

exit(0)
