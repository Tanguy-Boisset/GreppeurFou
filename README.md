# GreppeurFou - A CTF flag finder

Ever tried to grep your way to victory in a CTF challenge by using the common prefix of the flags ?

This tool does it for you but with a lot more chance to find the flag by testing all sort of variations : encodings, encryption...

It will also gather any useful information that could lead your research : IP addresses, hashes, passwords...

## Basic usage

Let's say you are part of a CTF where all flags follow some regex with a common prefix : `CTF{[A-Za-z0-9!?_]*}`\
You can use this prefix to find the flag easily in a `challenge.data` file (or any other type of file), by testing all kinds of encodings for example.\
To do that, simply run :

```
$ python3 greppeurFou.py challenge.data CTF

[*] Pre-calculating all flag formats
[*] Looking for flags in challenge.data

[+] FLAG FOUND in BASE64 in challenge.data, line 37:
    xercitation ullamco Q1RGe3RoaXNfaXNfYV9mbGFnX2luX2Jhc2U2NCF9 nisi ut aliquip ex 
    Decoded : CTF{this_is_a_flag_in_base64!}

```

## Detailled commands

```
   ______                                              ______             
  / ____/_____ ___   ____   ____   ___   __  __ _____ / ____/____   __  __
 / / __ / ___// _ \ / __ \ / __ \ / _ \ / / / // ___// /_   / __ \ / / / /
/ /_/ // /   /  __// /_/ // /_/ //  __// /_/ // /   / __/  / /_/ // /_/ / 
\____//_/    \___// .___// .___/ \___/ \__,_//_/   /_/     \____/ \__,_/  
                 /_/    /_/                                               v0.4
                                                                          by Sopalinge

usage: greppeurFou.py [-h] [-v] [-r] [-p PASSWORD] [-d DELIMITER] file flag_header

This tool will try to find flags using the usual CTF{xxxxx} format of many CTF challenges

positional arguments:
  file                  file to inspect
  flag_header           first few characters of the flag

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         verbose output
  -r, --recursive       search recursively in a folder
  -p PASSWORD, --password PASSWORD
                        try different techniques with a password
  -d DELIMITER, --delimiter DELIMITER
                        delimiter for the flag (default : {})
```

## Current and ongoing features

- [ ] Encodings
  - [x] Cleartext
  - [x] URL encoded
  - [ ] Octal
  - [x] Decimal
  - [x] Hexadecimal
  - [x] Base32
  - [x] Base64
  - [x] Base64 - URL proof
  - [x] Base85
  - [ ] BaseXX - flag hidden in bigger text
  - [ ] Braille
  - [ ] Morse
  - [x] UTF-16
- [ ] Encryption
  - [ ] XOR
  - [x] ROT13
  - [ ] ROTxx
  - [ ] Vigenère
- [ ] Info gathering
  - [x] IP addresses
  - [ ] Hashes
  - [x] URL
  - [ ] Domain names
  - [ ] Usernames
  - [x] Emails
  - [ ] Passwords

## Credits

Regex & inspiration : https://github.com/piratesecurity/CTF-Capture-The-Flag-/blob/master/Grep%20Commands
