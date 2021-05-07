import sqlite3
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from itertools import product
from string import ascii_lowercase
import sys
import base64



def main():
	if(len(sys.argv)) != 2:
		cur= sqlite3.connect('db.sqlite3').cursor()
		cur.execute("SELECT * from auth_user")
		p_data = cur.fetchall()
		PASSWORDS = [
        	"123456","123456789","qwerty","password","1234567","12345678","12345",
        	"iloveyou","111111","123123","abc123","qwerty123","1q2w3e4r","admin",
        	"qwertyuiop","654321","555555","lovely","7777777","welcome","888888",
        	"princess","dragon","password1","123qwe"]
		for p in PASSWORDS:
			for password in p_data:
				pass_data = password[1].split('$')
				kdf = PBKDF2HMAC(
					algorithm = hashes.SHA256(),
					length = 32,
					salt = pass_data[2].encode(),
					iterations = int(pass_data[1]),
				)
				if  kdf.derive(p.encode()) == base64.b64decode(pass_data[3]):
					print(password[4] + "," + p)
	else: 
		found = False	
		pass_data = sys.argv[1].split('$')
		count = 1
		while count < 5:
			for i in product(ascii_lowercase, repeat = count):
				password = ''.join(i)
				kdf = PBKDF2HMAC(
					algorithm=hashes.SHA256(),
					length=32,
					salt = pass_data[2].encode(),
					iterations=int(pass_data[1]),
				)
				if kdf.derive(password.encode()) == base64.b64decode(pass_data[3]):
					print('Password cracked: ' + password)
					found = True
			count += 1
		if found == False:
			print('Password not cracked.')

if __name__ == "__main__":
	main()