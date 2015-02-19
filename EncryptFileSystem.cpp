#include <stdio.h>
#include <string>
#include <iostream>
#include <clocale>
#include <cstdlib>
#include <fstream>
#include <time.h>
#include <Windows.h>
#include <tchar.h>
#include <vector>
#include <string>

#include "BufferCrypt.h"
#include "sha256.h"

//Compute the hash SHA256 of msg
void SHA256(Twofish_Byte* msg, int lenmsg, Twofish_Byte* sha256sum)
{
	sha256_context ctx;

	sha256_starts(&ctx);
	sha256_update(&ctx, msg, lenmsg);
	sha256_finish(&ctx, sha256sum);
}

//Convert an integer to char* in base 256
void Int2Block(unsigned int n, char* block)
{
	int i ;
	
	for (i=0 ; i<16 ; i++)
	{
		block[i] = n % 256 ;
		n /= 256 ;
	}
}

//Convert a char* to an int in base 256
unsigned int Block2Int(char* block)
{
	unsigned int n = 0 ;
	int i ;
	
	for (i=15; i>=0; i--)
	{
		n *= 256 ;
		n += (unsigned char)block[i] ;
	}

	return n ;
}

void ZeroBlock(char* block)
{
	for (int i=0; i<16; i++)
	{
		block[i] = 0 ;
	}
}

/*Encrypt the file "pathfilename".
It uses twofish for encryption with password "password".
It puts the encrypted file in the directory basepath with filename "cryptedfilename"
*/
bool EncryptFileTF(TypPath basepath, TypPath pathfilename, TypPass password, TypPath cryptedfilename)
{
	char N[16], block[16] ;
	std::ifstream f ;
	int i, n, k ;
	char Shead[16] = "SLYCRYPTSLYCRYP" ;
	Shead[15] = 'T' ;
	Twofish_key xps;
	Twofish_Byte ps[32] ;
	char pathcryptedfilename[1000] ;

	SHA256((Twofish_Byte*)password, strlen(password), ps) ;
	
	Twofish_prepare_key(ps, 32, &xps) ;

	f.open(pathfilename, std::ifstream::binary) ;
	f.seekg(0, f.end) ;
	n = (int)f.tellg() ;
	
	f.seekg(0, f.beg) ;
	f.read(block, 16) ;
	i = 0 ;
	if (f.gcount()==16)
	{
		for (i=0; i<16; i++)
		{
			if (block[i] != Shead[i])
			{
				break ;
			}
		}
	}
	f.close() ;
	if (i == 16)
	{
		return false;
	}

	sprintf_s(pathcryptedfilename, LENTYPPATH, "%s%s", basepath, cryptedfilename) ;
	BufferCrypt buffer(100*16, pathcryptedfilename, &xps) ;
	
	Int2Block(n, N) ;
	buffer.WriteHeader(Shead, 16) ;
	buffer.WriteHeader(N, 16) ;
	buffer.WriteHeader(buffer.IV, 16) ;

	buffer.Add(pathfilename, strlen(pathfilename) + 1) ;
	
	f.open(pathfilename, std::ifstream::binary) ;
	f.seekg(0, f.beg) ;
	while (true)
	{
		f.read(block, 16) ;
		k = (int)f.gcount() ;
		if (k==0)
		{
			break ;
		}
		buffer.Add(block, k) ;
	}
	f.close() ;

	buffer.Finish() ;

	return true ;
}

/*Reverse of the function EncryptFileTF:
Decrypt the file "pathfilename" with twofish and pasword "password".
It puts the decrypted file where it was before encryption (this info was encrypted in the file).
The output "pathfilenameout" contains the path and the name of the decrypted file.
"tempdir" is a directory where the temporary file is written.
*/
bool DecryptFileTF(TypPath pathfilename, TypPass password, TypPath tempdir, TypPath pathfilenameout)
{
	std::ifstream f ;
	std::ofstream g ;
	char block[16], blockt[16] ;
	char Shead[16] = "SLYCRYPTSLYCRYP" ;
	char N[16], IV[16] ;
	Shead[15] = 'T' ;
	int i ;
	unsigned int n ;
	Twofish_key xps;
	Twofish_Byte ps[32] ;

	SHA256((Twofish_Byte*)password, strlen(password), ps) ;	
	Twofish_prepare_key(ps, 32, &xps) ;

	f.open(pathfilename, std::ifstream::binary) ;
	f.read(block, 16) ;

	for (i=0; i<16; i++)
	{
		if (block[i] != Shead[i])
		{
			f.close() ;
			return false;
		}
	}
	
	f.read(N, 16) ;
	n = Block2Int(N) ;
	f.read(IV, 16) ;

	TypPath pathplainfilename ;
	TypPath filenameout ;

	bool GetName = true ;
	int k = 0;
	while (GetName)
	{
		f.read(block, 16);
		if (f.gcount()==0)
		{
			break ;
		}
		
		Twofish_decrypt(&xps, (Twofish_Byte*)block, (Twofish_Byte*)blockt) ;
		XOR(blockt, IV) ;
		
		for (i=0; i<16; i++)
		{
			if (blockt[i]==0)
			{
				GetName = false ;
				i++ ;
				break ;
			}
		}

		memcpy(pathplainfilename+k, blockt, i) ;
		k+=i ;
		if (!GetName)
		{
			pathplainfilename[k] = 0 ;
		}

		memcpy(IV, block, 16) ;
	}

	sprintf_s(pathfilenameout, LENTYPPATH, "%s", pathplainfilename) ;

	int ind = strlen(pathplainfilename) ;
	while (pathplainfilename[ind]!='\\' && ind>=0)
	{
		ind--;
	}
	sprintf_s(filenameout, LENTYPPATH, "%s%s", tempdir, pathplainfilename + ind + 1) ;
	g.open(filenameout, std::ofstream::binary) ;
	g.write(blockt+i, 16-i) ;
	n -= 16-i ;
	while (true)
	{
		f.read(block, 16);
		if (f.gcount()==0)
		{
			break ;
		}
		
		Twofish_decrypt(&xps, (Twofish_Byte*)block, (Twofish_Byte*)blockt) ;
		XOR(blockt, IV) ;
		
		if (n>=16)
		{
			g.write(blockt, 16) ;
			n-=16 ;
		}
		else
		{
			g.write(blockt,n) ;
			n = 0 ;
		}

		memcpy(IV, block, 16) ;
	}
	
	g.close() ;
	f.close() ;

	return true ;
}

// Make a list of all the files in the directory "path".
void ListDir(TypPath path, std::vector<WIN32_FIND_DATA>* listdir )
{
	HANDLE f ;
	WIN32_FIND_DATA fd ;
	TypPath search_path ;
	
	sprintf_s(search_path, LENTYPPATH, "%s*.*", path) ;
	
	f = ::FindFirstFile(search_path, &fd) ;

	if (f != INVALID_HANDLE_VALUE)
	{
		do
		{
			if (strcmp(fd.cFileName,".") && strcmp(fd.cFileName,".."))
			{
				listdir->push_back(fd) ;
			}
		}
		while (::FindNextFile(f, &fd)) ;

		::FindClose(f);
	}
}

//Tell if the directory "path" exists.
bool DirectoryExists(TypPath path)
{
  DWORD attrib = GetFileAttributes(path);

  return (attrib != INVALID_FILE_ATTRIBUTES && (attrib & FILE_ATTRIBUTE_DIRECTORY));
}

// Create the directory "path" with all the branchs before it.
void CreatePath(TypPath path)
{
	TypPath courant ;
	int end = strlen(path) - 1 ;

	sprintf_s(courant, LENTYPPATH, path) ;

	courant[end] = 0 ;
	while (!DirectoryExists(courant))
	{
		end -= 1 ;
		while (courant[end] != '\\')
		{
			end-- ;
		}
		courant[end] = 0 ;
	}

	while (strlen(courant) < strlen(path) - 1 )
	{
		courant[strlen(courant)] = '\\' ;
		CreateDirectory(courant, NULL) ;
	}
}

/*Reconstruct a directory from all the enrypted files in the directory "path".
It uses the password "password" to decrypt the files and the directory "tempdir"
for temporary files.
*/
void DecryptDirectory(TypPath path, TypPath password, TypPath tempdir)
{
	TypPath pathfilename ;
	TypPath pathfilenameout ;
	TypPath pathfilenamein ;
	TypPath pathout ;
	int end ;
	std::vector<WIN32_FIND_DATA> listdir;
	std::ifstream src ;
	std::ofstream dst ;
	CreatePath(tempdir) ;
	ListDir(path, &listdir) ;
	
	for (auto file = listdir.begin(); file != listdir.end(); file++)
	{
		sprintf_s(pathfilename, LENTYPPATH, "%s%s", path, file->cFileName);
		if (DecryptFileTF(pathfilename, password, tempdir, pathfilenameout))
		{
			sprintf_s(pathout, LENTYPPATH, "%s", pathfilenameout) ;
			end = strlen(pathfilenameout) ;
			while (pathout[end] != '\\')
			{
				end-- ;
			}
			end++ ;
			char t = pathout[end] ;
			pathout[end] = 0 ;
			CreatePath(pathout) ;
			pathout[end] = t ;

			sprintf_s(pathfilenamein, LENTYPPATH, "%s%s", tempdir, pathout + end) ;
			src.open(pathfilenamein, std::ios::binary) ;
			dst.open(pathfilenameout, std::ios::binary) ;
			dst << src.rdbuf();
			src.close() ;
			dst.close() ;
			
			remove(pathfilenamein) ;
			remove(pathfilename) ;
		}
	}

	RemoveDirectory(tempdir) ;
}

/*Encrypt a whole directory.
It takes recursively every file in the directory "basepath", encrypt them, and put them in the "basepath" directory
with a integer as name (the first encrypted file will have "index" as name).
*/
void EncryptDirectory(TypPath basepath, TypPath path, TypPass password, int* index)
{
	std::vector<WIN32_FIND_DATA> listdir;
	TypPath pathfilename ;
	TypPath cryname ;

	ListDir(path, &listdir) ;

	for (auto file = listdir.begin(); file != listdir.end(); file++)
	{
		sprintf_s(pathfilename, LENTYPPATH, "%s%s", path, file->cFileName);
		if (file->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			sprintf_s(pathfilename, LENTYPPATH, "%s\\", pathfilename);
			EncryptDirectory(basepath, pathfilename, password, index) ;
		}
		else
		{
			sprintf_s(cryname, LENTYPPATH, "%d", *index) ;
			if (EncryptFileTF(basepath, pathfilename, password, cryname))
			{
				if (remove(pathfilename))
				{
					printf("Impossible to remove %s\n", pathfilename) ;
				}
				*index += 1 ;
			}
		}
	}

	for (auto file = listdir.begin(); file != listdir.end(); file++)
	{
		if (file->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			sprintf_s(pathfilename, LENTYPPATH, "%s%s\\", path, file->cFileName);
			if (!RemoveDirectory(pathfilename))
			{
				printf("Impossible to delete %s\n", pathfilename) ;
			}
		}
	}
}

void main(int nargs,char* args[])
{
	TypPath basepath ;
	TypPath path ;
	TypPass password ;
	TypPath tempdir ;
	int index = 0;

	srand((unsigned int)time(NULL));
	Twofish_initialise() ;
	
	if (nargs < 4)
	{
		printf("Syntaxe : \n") ;
		printf("To Encrypt directory with password : EncryptFileSystem /D directory password\n") ;
		printf("To Decrypt directory with password : EncryptFileSystem /E directory password\n") ;
		return ;
	}
	sprintf_s(password, LENPASS, args[3]);
	sprintf_s(basepath, LENTYPPATH, "%s", args[2]) ;
	if (args[2][strlen(args[2])-1]!='\\')
	{
		sprintf_s(basepath, LENTYPPATH, "%s\\", basepath) ;
	}
	sprintf_s(tempdir, LENTYPPATH, "%s%s\\", basepath, "SLYCRYPT") ;

	if (!strcmp(args[1],"/E"))
	{
		EncryptDirectory(basepath, basepath, password, &index) ;
	}
	else if (!strcmp(args[1], "/D"))
	{
		DecryptDirectory(basepath, password, tempdir) ;
	}
}
