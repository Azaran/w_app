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
#include "rijndael.h"
#include "crc.h"
#include "sha256.h"
using namespace std;


SevenZCrackerCPU::SevenZCrackerCPU(SevenZInitData *data):check_data(*data){ 

    int coder = 0; 

    cout << "IV: " << endl;
    for (uint8_t i = 0; i < data->folders[0].coder[coder].propertySize-2; i++) 
    {
	iv[i] = data->folders[0].coder[coder].property[i+2];
	cout << hex << (int) iv[i] << " ";
    }
    cout << endl;
    this->destlen = data->folders[0].unPackSize[1];
    this->srclen = data->packInfo->packSize[0];
    cout << endl;
    cout << "destlen: " << destlen << endl;
    cout << "srclen: " << srclen-15 << endl;
    this->raw = new uint8_t[destlen];
    this->data = new uint8_t[srclen];
    //rdData = new uint8_t [check_data.erdSize];
    //tempKey = new uint8_t [check_data.ivSize + check_data.erdSize];
    //vData = new uint8_t [check_data.encSize];
}

SevenZCrackerCPU::SevenZCrackerCPU(const SevenZCrackerCPU& orig){}

SevenZCrackerCPU::~SevenZCrackerCPU(){
}

CheckResult SevenZCrackerCPU::checkPassword(const std::uint8_t* pass) {
    
    ELzmaStatus status;
    SRes decode;
    Rijndael aes;
    ISzAlloc alloc = { SzAlloc, SzFree };

    derive(pass, (uint8_t*)key);
    cout << "key: " << endl;
    for (int i = 0; i < 32; i++)
	cout << std::hex <<(int) key[i] << " ";
    std::cout << std::endl; 	
    aes.Init(false, key, check_data.keyLength, (uint8_t*)iv);
    aes.blockDecrypt(check_data.encData, srclen, data);
    for (uint64_t i =0; i < srclen; i++)
	cout << hex << (int)data[i] << " " ;
    cout << endl;
    cout << endl;
    srclen-=15; 
    decode = LzmaDecode(raw, &destlen,\
	    data, &srclen,\
	    check_data.folders[0].coder[0].property,\
	    check_data.folders[0].coder[0].propertySize,\
	    LZMA_FINISH_END, &status, &alloc);
    cout << "decode: " << decode << endl;
    cout << "status: " << status << endl;
    uint32_t *crc;
    if (check_data.packInfo->crc != NULL)
        cout << "crc" << check_data.packInfo->crc << endl;  
    else{
	cerr << "I couldnt find CRC in data structure." << endl;
	exit(155);
    }
    cout << "crccomp: " << crc32(0, raw, destlen) << endl;
    cout <<"crc: " << crc[0] << endl;
    if (crc[0] == crc32(0, raw, destlen))
	return CR_PASSWORD_MATCH;
    
    return CR_PASSWORD_WRONG;
}

void SevenZCrackerCPU::prepareKey(const uint8_t* pass, uint8_t* key){
    std::ostringstream buffer; 
    uint64_t i = 0;
    uint64_t iter = 1 << 19; // 2^19
    // https://sourceforge.net/p/sevenzip/discussion/45797/thread/26314871/
    // delka klice pri delce hesla 1 (1+8)*524288 = 4,718,592 znaku
    // delka klice pri delce hesla 8 (8+8)*524288 = 8,388,608 znaku 
    //

    cout << "passlen is: " << pass->length() << endl;    
    while ( i < iter)
	buffer << setw(16) << new_pass << setw(8) << setfill('0') << i++; 
    cout << "last iter:" << hex << setw(2)<< setfill('0')<< new_pass  << setw(8) << setfill('0') << i;
    *key = buffer.str();
}


void SevenZCrackerCPU::derive(const uint8_t* pass, uint8_t* output){
    
    uint8_t hash1[32];
    uint8_t hash2[32];
    uint8_t *hash1ptr = (uint8_t*) hash1;
    uint8_t *hash2ptr = (uint8_t*) hash2;
    uint64_t iter = (1 << 19);
    cout << dec << "iter: " << iter << endl;
    string key;
    uint64_t keylen;
    prepareKey(pass, &key);
    sha256(reinterpret_cast<const uint8_t*>(key.c_str()),key.length(), (uint8_t*)hash1ptr);
    while (--iter > 0 ){
	sha256((const uint8_t*)hash1ptr, 32, hash2ptr);
	std::swap(hash1ptr, hash2ptr);	
    }
    cout << dec << "iter: " << iter << endl;
    memcpy(output, hash1ptr, 32);
}
void convertKey(const uint8_t* pass, uint8_t** key){
    
    uint8_t key = new uint8_t[2*pass->length()];
    for (int i; i < pass->length(); i++)
    {
	new_pass[i*2] = (pass->c_str())[i];
	new_pass[i*2+1] = 0;
    }
}
