/* 
 * Copyright (C) 2016 Vojtech Vecera
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy 
 * of this software and associated documentation files (the "Software"), to deal 
 * in the Software without restriction, including without limitation the rights 
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
 * copies of the Software, and to permit persons to whom the Software is 
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in 
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
 * SOFTWARE.
 * 
 */

#include "SevenZFormat.h"
#include "SevenZCrackerCPU.h"
#include <deque>
#include <sstream>
#include <iostream>
#include "Aes.h"
#include "7zCrc.h"
#include "Sha256.h"
using namespace std;


SevenZCrackerCPU::SevenZCrackerCPU(SevenZInitData *data):check_data(*data){ 

    
    int coder = 0; 
    for (uint8_t i = 0; i < data->folders[0].coder[coder].propertySize-2; i++)   
	iv[i] = data->folders[0].coder[coder].property[i+2];
    if (data->folders[0].numCoders == 1){
	this->destlen = data->folders[0].unPackSize[0];
    } else { 
	this->destlen = data->folders[0].unPackSize[1];
    }

    this->srclen = data->packInfo->packSize[0];
//    cout << "destlen: " << destlen<< endl;
//    cout << "srclen: " << srclen << endl;
    this->data = new uint8_t[srclen];
    AesGenTables();
    CrcGenerateTable();
}

SevenZCrackerCPU::SevenZCrackerCPU(const SevenZCrackerCPU& orig){}

SevenZCrackerCPU::~SevenZCrackerCPU(){
}

CheckResult SevenZCrackerCPU::checkPassword(const std::string* pass) {
   
    convertKey(pass);
    hash(key);
    ELzmaStatus status;
    SRes decode;
    uint32_t *aes = new uint32_t[AES_NUM_IVMRK_WORDS+3];
    *aes = {0};
    uint8_t first_block[DECODE_BLOCK_SIZE];
    ISzAlloc alloc = { SzAlloc, SzFree };
    SizeT dlen = destlen;
    SizeT slen = srclen;
   
    if (slen > 2*DECODE_BLOCK_SIZE){
	// Decrypt first block and check if first byte is 0
	memcpy(first_block, check_data.encData, DECODE_BLOCK_SIZE);

	decrypt(aes, first_block, 1);

	if (check_data.folders[0].numCoders != 1 && first_block[0] != 0)
	    // For LZMA first byte is always 0
	    return CR_PASSWORD_WRONG;
	else if (check_data.folders[0].numCoders == 1 && (first_block[0] != 1 || first_block[1]!= 4))
	    // When header is not compressed check whether the first 2 bytes are 0x04 and 0x06
	    return CR_PASSWORD_WRONG;
    }
    memcpy(data, check_data.encData, slen); 
    decrypt(aes, data, slen / DECODE_BLOCK_SIZE);
    if (check_data.folders[0].numCoders != 1){
        this->raw = new uint8_t[destlen];
        decode = LzmaDecode(raw, &dlen,\
                data, &slen,\
                check_data.folders[0].coder[1].property,\
                check_data.folders[0].coder[1].propertySize,\
                LZMA_FINISH_ANY, &status, &alloc);
    
    } else if(check_data.folders[0].numCoders == 1) 
        raw = data;

    uint32_t *crc;
    if (check_data.packInfo->crc != NULL)
        crc = check_data.packInfo->crc;  
    else{
	cerr << "I couldnt find CRC in data structure." << endl;
	exit(155);
    }
    
    uint64_t endOfCRCBlock = dlen;
    if (check_data.subStreamSize != NULL)
        endOfCRCBlock = check_data.subStreamSize[0];
    
    if (crc[0] == CrcCalc(raw, endOfCRCBlock))
	return CR_PASSWORD_MATCH;
    
    return CR_PASSWORD_WRONG;
}

void SevenZCrackerCPU::decrypt(uint32_t* aes, uint8_t* data, uint64_t len){
    
    int offset = ((0 - (unsigned)(ptrdiff_t)aes) & 0xf) / sizeof(uint32_t);
    AesCbc_Init(aes+offset, iv);
    Aes_SetKey_Dec(aes+offset+4, key, AES_KEY_SIZE);
    g_AesCbc_Decode(aes+offset, data, len); 
}

void SevenZCrackerCPU::hash(uint8_t* output){

    CSha256 sha;
    Sha256_Init(&sha);
    
    uint8_t *ctr = password + passSize-8;
    uint64_t numRounds = 1 << 19;
    while (numRounds--)
    {
	Sha256_Update(&sha, password, passSize);
	for (unsigned i = 0; i < 8; i++)
	    if (++(ctr[i]) != 0)
		break;
    }
    Sha256_Final(&sha, output);
}

void SevenZCrackerCPU::convertKey(const string* pass){
    
    if ( 2*pass->length()+8 > passSize){
	delete[] password;
	passSize = 2*pass->length() + 8; 
	password = new uint8_t[passSize];
    }
//    cout << hex << "passSize: " << passSize << endl;
    int i;
    for (i=0; i < pass->length(); i++){
	password[i*2] = (int)(pass->c_str())[i];
	password[i*2+1] = 0;
//	cout << " p: " << (int) password[i*2];
//	cout << " p1: " << (int) password[i*2 +1];
    }
    for (i = i*2; i < passSize; i++){
	password[i] = 0;
    }
}
