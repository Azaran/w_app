#! /usr/bin/env python
# Estimate password cracking time
# author: Radek Hranicky

import math

# Calculates the lex. position of password
def calc_lexPos(password, charDict):
    pos = 0
    print("---------")
    for i in range(0,len(password)):
        pos += charDict[password[len(password) - (i+1)]] * pow(len(charDict), i)
    return pos
        
# Makes a dictionary of character "values" in lexicographical order
def make_charDict(chars):
    charDict = dict()
    char_count = 1
    for char in chars:
        if char in charDict.keys():
            print("Error: Duplicate occurence of a single character!")
            exit(1)
        charDict[char] = char_count
        char_count += 1
    return charDict

# Validate if given password contains only characters from dictionary
def validatePassword(password, charDict):
    for char in password:
        if not char in charDict.keys():
            return False
    return True


print("=== Cracking time estimation ===")
try:
    speed = int(raw_input("Enter cracking speed (pass/s): "))
except ValueError:
    print("Error: Cracking speed must be an integer!")
    exit(1)
    
chars = raw_input("Enter characters in lexicographical order [default: abcdefghijklmnopqrstuvwxyz]: ")
if chars == "":
    chars = "abcdefghijklmnopqrstuvwxyz"
charDict = make_charDict(chars)

password = raw_input("Enter password: ")

if not validatePassword(password,charDict):
    print("Error: Password contains undefined characters!")
    exit(1)
    
combinations = calc_lexPos(password,charDict)

print("--------------------------------")
print("Total combinations to be computed: " + str(combinations))

seconds = float(combinations) / float(speed)

years = int(seconds / 31536000)
seconds = seconds % 31536000

days = int(seconds / 86400)
seconds = seconds % 86400

hours = int(seconds / 3600)
seconds = seconds % 3600

minutes = int(seconds / 60)
seconds = seconds % 60

print("Estimated cracking time: ")
if years > 0:
    print(str(years) + " y")
if days > 0:
    print(str(days) + " d")
if hours > 0:
    print(str(hours) + " h")
if minutes > 0:
    print(str(minutes) + " m")
if seconds > 0:
    print(str(round(seconds,2)) + " s")

