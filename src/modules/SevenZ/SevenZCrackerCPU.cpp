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
    this->raw = new uint8_t[destlen];
    this->data = new uint8_t[srclen];
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
    ISzAlloc alloc = { SzAlloc, SzFree };
    SizeT dlen = destlen;
    SizeT slen = srclen;
/*
    cout << "key: " << endl;
    for (int i = 0; i < 32; i++)
	cout << std::hex <<(int) key[i] << " ";
    std::cout << std::endl; 

    for (int i = 0; i < passSize; i++)
	cout << std::hex <<(int) password[i] << " ";
    std::cout << std::endl; 	
    for (int i = 0; i < 16; i++)
	cout << hex << (int) iv[i] << " ";
    std::cout << std::endl; 	
*/
    
    memcpy(data, check_data.encData, slen); 
   
    int offset = ((0 - (unsigned)(ptrdiff_t)aes) & 0xF) / sizeof(UInt32);
    
    AesGenTables();
    AesCbc_Init(aes+offset, iv);
    Aes_SetKey_Dec(aes+offset+4, key, 32);
    g_AesCbc_Decode(aes+offset, data, slen/16);
/*
    for (uint64_t i = 0; i < slen; i++)
    {
	if ( i%16 == 0)
	    cout << endl;
	if ( i%8 == 0)
	    cout << " ";
	cout << hex << setw(2) << setfill('0') << (int)check_data.encData[i] << " " ;
    } 
    cout << endl;
    cout << endl;
    for (uint64_t i =0; i < slen; i++)
    {
	if ( i%16 == 0)
	    cout << endl;
	if ( i%8 == 0)
	    cout << " ";
	cout << hex << setw(2) << setfill('0') << (int)data[i] << " " ;
    } 
    cout << endl;
    cout << endl;
*/

    if ( check_data.folders[0].numCoders != 1)
    {
	decode = LzmaDecode(raw, &dlen,\
		data, &slen,\
		check_data.folders[0].coder[1].property,\
		check_data.folders[0].coder[1].propertySize,\
		LZMA_FINISH_ANY, &status, &alloc);
/*	
	for (uint64_t i =0; i < dlen; i++)
	{
	    if ( i%16 == 0)
		cout << endl;
	    if ( i%8 == 0)
		cout << " ";
	    cout << hex << setw(2) << setfill('0') << (int)raw[i] << " " ;
	}
	cout << endl;
	ofstream out;
	out.open("new.txt", ios::binary | ios::out | ios::trunc);
	for (uint64_t i =0; i < dlen; i++)
	{
	    out << raw[i];
	} 
	out.close();
	    cout << "decode: " << decode << endl;
	    cout << "status: " << status << endl;
	    cout << "dlen: " << dlen << endl;
	    cout << "dlen2: " << dlen2 << endl;
	    cout << "slen: " << slen << endl;
	    cout << "slen2: " << check_data.packInfo->packSize[0] << endl;
	cout << "propsize: " << check_data.folders[0].coder[1].propertySize << endl;
	for (uint64_t i =0; i < 5; i++)
	    cout << hex << setw(2) << setfill('0') << (int)check_data.folders[0].coder[1].property[i] << " " ;
	cout << endl;
  */  
    
    } else raw = data;


    uint32_t *crc;
    if (check_data.packInfo->crc != NULL)
        crc = check_data.packInfo->crc;  
    else{
	cerr << "I couldnt find CRC in data structure." << endl;
	exit(155);
    }
    
    CrcGenerateTable();
//    cout << "pass: " << *pass << endl;
    uint64_t endOfCRCBlock = dlen;
    if (check_data.subStreamSize != NULL)
        endOfCRCBlock = check_data.subStreamSize[0];
//    cout << "crccomp: " << CrcCalc(raw, endOfCRCBlock) << endl;
//    cout <<"crc: " << crc[0] << endl;
    
    if (crc[0] == CrcCalc(raw, endOfCRCBlock))
	return CR_PASSWORD_MATCH;
    
  //  exit(0);
    return CR_PASSWORD_WRONG;
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
    for (i = i*2+1;i<passSize; i++){
	password[i] = 0;
    }
}
