# EncryptFileSystem
Command line tool to encrypt/decrypt a whole file system.
The goal is to be able to put an entire file system in an insecure cloud and manage it file by file.
For example, say you want to encrypt the directory "dir1" :

dir1

  |
  
  ---a.txt
  
  ---b.txt
  
  ---dir2
  
     |
     
     ---c.txt
     
     ---d.exe
     
     ---dir3
     
        |
        
        ---f.pdf

The result will be :

dir1

  |
  
  ---0
  
  ---1
  
  ---2
  
  ---3
  
  ---4
  
  ---5
  
where the files 0, 1, 2, 3, 4 and 5 are the encrypted versions of a.txt, b.txt, c.txt, d.exe and f.pdf.
The path of each file is an information that is also encrypted in the files. So the tree of directories is protected.

Syntaxe :
	
	To Encrypt directory with password : EncryptFileSystem /D directory password
	
	To Decrypt directory with password : EncryptFileSystem /E directory password

Example :

	EncryptFileSystem /D c:\temp password
	
	EncryptFileSystem /E c:\temp password
	
To do list :

1) Generate a index file to have a link between the name of the encrypted file and the name of the decrypted file.

2) Be able to split big files into little encrypted files so that downloading them is easier.

3) Put the files attributes and informations (creation date, modification date, ...) in the encrypted files so that, when they are decrypted, the files recovers all their properties (for the moment, I don't know how to do it in C++).
