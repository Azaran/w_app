#ifndef _RIJNDAEL_H_
#define _RIJNDAEL_H_

#include <cstdint>
#include <stdlib.h>

/**************************************************************************
 * This code is based on Szymon Stefanek AES implementation:              *
 * http://www.esat.kuleuven.ac.be/~rijmen/rijndael/rijndael-cpplib.tar.gz *
 *                                                                        *
 * Dynamic tables generation is based on the Brian Gladman's work:        *
 * http://fp.gladman.plus.com/cryptography_technology/rijndael            *
 **************************************************************************/

#define _MAX_KEY_COLUMNS (256/32)
#define _MAX_ROUNDS      14
#define MAX_IV_SIZE      16

class Rijndael
{ 
  private:
    void keySched(uint8_t key[_MAX_KEY_COLUMNS][4]);
    void keyEncToDec();
    void GenerateTables();

    // RAR always uses CBC, but we may need to turn it off when calling
    // this code from other archive formats with CTR and other modes.
    bool     CBCMode;
    
    int      m_uRounds;
    uint8_t     m_initVector[MAX_IV_SIZE];
    uint8_t     m_expandedKey[_MAX_ROUNDS+1][4][4];
  public:
    Rijndael();
    void Init(bool Encrypt,const uint8_t *key, unsigned int keyLen,const uint8_t *initVector);
    void blockEncrypt(const uint8_t *input, size_t inputLen, uint8_t *outBuffer);
    void blockDecrypt(const uint8_t *input, size_t inputLen, uint8_t *outBuffer);
    void SetCBCMode(bool Mode) {CBCMode=Mode;}
};
  
#endif // _RIJNDAEL_H_
