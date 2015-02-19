#include <fstream>

#include "twofish.h"

#define LENTYPPATH 1000
#define LENPASS 256

typedef char TypPath[LENTYPPATH] ;
typedef char TypPass[LENPASS] ;

void XOR(char* a, char* b) ;

/* A class to write encrypted block in a file*/
class BufferCrypt
{
public :
	char* plain ;
	unsigned int size, maxsize, debut ;
	char IV[16] ;
	std::ofstream f ;
	Twofish_key* TFkey ;

	BufferCrypt(unsigned int n, char* filename, Twofish_key* xps) ;
	~BufferCrypt() ;
	bool WriteBlock() ;
	bool Add(char* block, unsigned int s) ;
	void WriteHeader(char* header, unsigned int s) ;
	void Finish() ;
} ;
