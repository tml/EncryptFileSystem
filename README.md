# EncryptFileSystem
Command line tool to encrypt/decrypt each file of a file system.
The goal is to be able to put an entire file system in an insecure cloud and manage it file by file.

Syntaxe :
	
	To Encrypt directory with password : EncryptFileSystem /D directory password
	
	To Decrypt directory with password : EncryptFileSystem /E directory password

Example :

	EncryptFileSystem /D c:\temp password
	
	EncryptFileSystem /E c:\temp password
	
Future features :

1) Generate a index file to have a link between the name of the encrypted file and the name of the decrypted file.

2) Be able to split big files into little encrypted files so that downloading them is easier.
