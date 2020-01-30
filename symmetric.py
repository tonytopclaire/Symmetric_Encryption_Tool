# ---------------------------------------------------------------------------------------------------------------------------------------------
# Assignment 1    Symmetric Encryption in Python
# Course:         INFR 3600U
# Author:         Shengqian Wang
# Student Number: 100474399
# Date:           09/18/2018
# Description:    Encryption using either AES or 3DES encryption
# ---------------------------------------------------------------------------------------------------------------------------------------------

import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
key = os.urandom(32)
user_msg = str.encode(input("The secret message is: "))

while True:
	try:
		user_option = input("Encryption options: 'A' for AES, 'D' for 3DES, please select one: ")
		#AES STARTS-------------------------------------------------------------------------------------------------------------------
		if user_option is 'A' or user_option is 'a' :
			def encrypt(key, plaintext, associated_data):
				# Generate a random 96-bit IV.
				iv = os.urandom(12)
				# Construct an AES-GCM Cipher object with the given key and a
				# randomly generated IV.
				encryptor = Cipher(
					algorithms.AES(key),
					modes.GCM(iv),
					backend=default_backend()
				).encryptor()
				# associated_data will be authenticated but not encrypted,
				# it must also be passed in on decryption.
				encryptor.authenticate_additional_data(associated_data)

				# Encrypt the plaintext and get the associated ciphertext.
				# GCM does not require padding.
				ciphertext = encryptor.update(plaintext) + encryptor.finalize()
				return (iv, ciphertext, encryptor.tag)
			def decrypt(key, associated_data, iv, ciphertext, tag):
				# Construct a Cipher object, with the key, iv, and additionally the
				# GCM tag used for authenticating the message.
				decryptor = Cipher(
					algorithms.AES(key),
					modes.GCM(iv, tag),
					backend=default_backend()
				).decryptor()

				# We put associated_data back in or the tag will fail to verify
				# when we finalize the decryptor.
				decryptor.authenticate_additional_data(associated_data)
				# Decryption gets us the authenticated plaintext.
				# If the tag does not match an InvalidTag exception will be raised.
				return decryptor.update(ciphertext) + decryptor.finalize()
			iv, ciphertext, tag = encrypt(
				key,
				user_msg,
				b"Authenticated but not encrypted payload"
			)
			print("------------------------------------------------------------------------------------------------")
			print("The Encrypted message with AES in GCM mode is: ")
			print ("\n")
			print(encrypt(
				key,
				user_msg,
				b"Authenticated but not encrypted payload"
			))
			print ("\n")
			print("The Decrypted message with AES in GCM mode is: ")
			print ("\n")
			print(decrypt(
				key,
				b"Authenticated but not encrypted payload",
				iv,
				ciphertext,
				tag
			))
			print("------------------------------------------------------------------------------------------------")
			break
		#AES ENDS-------------------------------------------------------------------------------------------------------------------
		#3DES STARTS-------------------------------------------------------------------------------------------------------------------
		elif user_option is 'D' or user_option is 'd':	
			backend = default_backend()
			key = os.urandom(16)
			text = user_msg
			padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()
			unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
			cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=backend)
			encryptor = cipher.encryptor()
			decryptor = cipher.decryptor()
			encrypted_text = encryptor.update(padder.update(text) + padder.finalize()) + encryptor.finalize()
			decrypted_text = unpadder.update(decryptor.update(encrypted_text) + decryptor.finalize()) + unpadder.finalize()
			print("------------------------------------------------------------------------------------------------")
			print("The Encrypted message with 3DES is: ")
			print ("\n")
			print(encrypted_text)
			print ("\n")
			print("The Decrypted message with 3DES is: ")
			print ("\n")
			print(decrypted_text)
			print("------------------------------------------------------------------------------------------------")
			break
		#3DES ENDS-------------------------------------------------------------------------------------------------------------------
		else:
			print("Oops! That was no valid number.  Try again...")	
	except ValueError:
		print("Oops! Something wrong.  Try again...")