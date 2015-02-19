#include "BufferCrypt.h"

void XOR(char* a, char* b)
{
	int i ;
	
	for (i=0; i<16 ;i++)
	{
		a[i] ^= b[i] ;
	}
}

void RandomBlock(char* block)
{
	int i;

	for (i=0; i<16; i++)
	{
		block[i] = rand() % 256 ;
	}
}

void BufferCrypt::WriteHeader(char* header, unsigned int s)
{
	f.write(header, s) ;
}

BufferCrypt::BufferCrypt(unsigned int n, char* filename, Twofish_key* xps) 
{
	size = 0 ;
	debut = 0 ;

	maxsize = n ;
	plain = new char[n] ;

	f.open(filename, std::ofstream::binary) ;

	RandomBlock(IV) ;
	TFkey = xps ;
}

BufferCrypt::~BufferCrypt()
{
	delete[] plain ;
	f.close() ;
}

bool BufferCrypt::Add(char* block, unsigned int s)
{
	if (size + s >= maxsize)
	{
		return false ;
	}

	if (debut + size + s >= maxsize)
	{
		for (unsigned int i = 0; i < size; i++)
		{
			plain[i] = plain[i+debut] ;
		}
		debut = 0 ;
	}

	memcpy(plain + debut + size, block, s) ;
	size += s ;

	while (WriteBlock())
	{
	}

	return true ;
}

//Write one encrypted block to the file.
bool BufferCrypt::WriteBlock()
{
	if (size>=16)
	{
		XOR(plain + debut, IV) ;
		Twofish_encrypt(TFkey, (Twofish_Byte*)(plain+debut), (Twofish_Byte*)IV) ;

		f.write(IV, 16) ;

		debut += 16 ;
		size -= 16 ;

		return true ;
	}
	else
	{
		return false ;
	}
}

//Complete the last block with 0.
void BufferCrypt::Finish()
{
	while (size % 16 != 0)
	{
		plain[debut + size++] = 0 ;
	}

	WriteBlock() ;
}
