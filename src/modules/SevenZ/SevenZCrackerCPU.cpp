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

    cout << "IV: " << endl;
    for (uint8_t i = 0; i < data->folders[0].coder[coder].propertySize-2; i++) 
    {
	iv[i] = data->folders[0].coder[coder].property[i+2];
    }
    cout << endl;
    this->destlen = data->folders[0].unPackSize[1];
    this->srclen = data->packInfo->packSize[0];
    cout << endl;
    cout << "destlen: " << destlen << endl;
    cout << "srclen: " << srclen << endl;
    this->raw = new uint8_t[destlen];
    this->data = new uint8_t[srclen];
    //rdData = new uint8_t [check_data.erdSize];
    //tempKey = new uint8_t [check_data.ivSize + check_data.erdSize];
    //vData = new uint8_t [check_data.encSize];
}

SevenZCrackerCPU::SevenZCrackerCPU(const SevenZCrackerCPU& orig){}

SevenZCrackerCPU::~SevenZCrackerCPU(){
}

CheckResult SevenZCrackerCPU::checkPassword(const std::string* pass) {
   
    if (!passwordSet){
	convertKey(pass);
	passwordSet = true;
    }

    ELzmaStatus status;
    SRes decode;
    uint32_t *aes = new uint32_t[AES_NUM_IVMRK_WORDS+3];
    *aes = {0};
    ISzAlloc alloc = { SzAlloc, SzFree };


    hash(key);
/*
    cout << "key: " << endl;
    for (int i = 0; i < 32; i++)
	cout << std::hex <<(int) key[i] << " ";
    std::cout << std::endl; 	
    for (int i = 0; i < 16; i++)
	cout << hex << (int) iv[i] << " ";
    std::cout << std::endl; 	
*/     
    memcpy(data, check_data.encData, srclen); 
    int offset = ((0 - (unsigned)(ptrdiff_t)aes) & 0xF) / sizeof(UInt32);
    
    AesGenTables();
    AesCbc_Init(aes+offset, iv);
    Aes_SetKey_Dec(aes+offset+4, key, 32);
    g_AesCbc_Decode(aes+offset, data, srclen/16);

    /*
    for (uint64_t i = 0; i < srclen; i++)
    {
	if ( i%16 == 0)
	    cout << endl;
	if ( i%8 == 0)
	    cout << " ";
	cout << hex << setw(2) << setfill('0') << (int)check_data.encData[i] << " " ;
    } 
    cout << endl;
    cout << endl;
    for (uint64_t i =0; i < srclen; i++)
    {
	if ( i%16 == 0)
	    cout << endl;
	if ( i%8 == 0)
	    cout << " ";
	cout << hex << setw(2) << setfill('0') << (int)data[i] << " " ;
    } 
    cout << endl;
    cout << endl;
    cout << "propsize: " << check_data.folders[0].coder[1].propertySize << endl;
    for (uint64_t i =0; i < 5; i++)
	cout << hex << setw(2) << setfill('0') << (int)check_data.folders[0].coder[1].property[i] << " " ;
*/    
    decode = LzmaDecode(raw, &destlen,\
	    data, &srclen,\
	    check_data.folders[0].coder[1].property,\
	    check_data.folders[0].coder[1].propertySize,\
	    LZMA_FINISH_ANY, &status, &alloc);
/*
    for (uint64_t i =0; i < destlen; i++)
    {
	if ( i%16 == 0)
	    cout << endl;
	if ( i%8 == 0)
	    cout << " ";
	cout << hex << setw(2) << setfill('0') << (int)raw[i] << " " ;
    } 
    cout << endl;
    cout << "decode: " << decode << endl;
    cout << "status: " << status << endl;
    cout << "destlen: " << destlen<< endl;
    cout << "srclen: " << srclen << endl;
    ofstream out;
    out.open("new.txt", ios::binary);
    for (uint64_t i =0; i < destlen; i++)
    {
	out << raw[i];
    } 
    out.close();
  */
    uint32_t *crc;
    if (check_data.packInfo->crc != NULL)
        crc = check_data.packInfo->crc;  
    else{
	cerr << "I couldnt find CRC in data structure." << endl;
	exit(155);
    }
    
    CrcGenerateTable();
    
    //cout << "crccomp: " << CrcCalc(raw, destlen) << endl;
    //cout <<"crc: " << crc[0] << endl;
    
    if (crc[0] == CrcCalc(raw, destlen))
	return CR_PASSWORD_MATCH;
    
    //exit(0);
    
    return CR_PASSWORD_WRONG;
}

void SevenZCrackerCPU::prepareKey(uint8_t* stretched_key){
    uint64_t i = 0;
    uint64_t iter = 1 << 19; // 2^19
    int step = 8+passSize;
    // https://sourceforge.net/p/sevenzip/discussion/45797/thread/26314871/
    // delka klice pri delce hesla 1 (2+8)*524288 = znaku
    // delka klice pri delce hesla 8 (16+8)*524288 =  znaku 
    //
    int j = 0;	
    while ( i < iter){
	for (j = 0; j < passSize; j++)
	    stretched_key[i*step+j] = password[j];
	memcpy(stretched_key+(i*step+j), &iter, 8);
	i++;
    }
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
    
    passSize = 2*pass->length() + 8; 
    password = new uint8_t[passSize];
    int i;
    for (i=0; i < pass->length(); i++){
	password[i*2] = (pass->c_str())[i];
	password[i*2+1] = 0;

    }
    for (;i<passSize; i++){
	password[i] = 0;
    }
}
