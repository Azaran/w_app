/* 
 * Copyright (C) 2014 Jan Schmied
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

#include "ZIPTDESCrackerCPU.h"
#include <deque>
#include <string.h>
#include <iostream>

ZIPTDESCrackerCPU::ZIPTDESCrackerCPU(std::vector<ZIPInitData> *data):data(data) {
    for(int i = 0;i<this->data->size();i++){
        if((*this->data)[i].dataLen > 0){
            check_data = (*(this->data))[i];
            break;
        }
    }
}

ZIPTDESCrackerCPU::ZIPTDESCrackerCPU(const ZIPTDESCrackerCPU& orig) {
}

ZIPTDESCrackerCPU::~ZIPTDESCrackerCPU() {
}

CheckResult ZIPTDESCrackerCPU::checkPassword(const std::string* pass) {
    uint8_t verifier[2];
    switch(check_data.keyLength){
        case 256: pbkdf2_sha1_zip_aes256(reinterpret_cast<const uint8_t*>(pass->c_str()),pass->length(),check_data.salt,verifier);break;
        case 128: pbkdf2_sha1_zip_aes128(reinterpret_cast<const uint8_t*>(pass->c_str()),pass->length(),check_data.salt,verifier);break;
        case 192: pbkdf2_sha1_zip_aes192(reinterpret_cast<const uint8_t*>(pass->c_str()),pass->length(),check_data.salt,verifier);break;
    }
    if(::memcmp(&check_data.verifier,verifier,2) == 0){
        uint8_t keyData[128],authCode[20];
        uint8_t *key;
        pbkdf2_sha1(reinterpret_cast<const uint8_t*>(pass->c_str()),pass->length(),check_data.salt,check_data.saltLen,1000,check_data.keyLength/4,keyData);
        key = keyData+(check_data.keyLength/8);
        hmac_sha1(check_data.encData,check_data.dataLen,key,check_data.keyLength/8,authCode);
        if(::memcmp(authCode,check_data.authCode,10) == 0){
            return CR_PASSWORD_MATCH;
        }
        return CR_PASSWORD_WRONG;
    }
    return CR_PASSWORD_WRONG;
}

#define ROL(x, n) ((x << n) | ((x) >> (sizeof(n)*8 - n)))

#define ROUNDTAIL(a,b,e,f,i,k,w)  \
	e += ROL(a,5) + f + k + w[i];  \
	b = ROL(b,30);

#define F1(b,c,d) (d ^ (b & (c ^ d)))
#define F2(b,c,d) (b ^ c ^ d)
#define F3(b,c,d) ((b & c) ^ (b & d) ^ (c & d))
#define F4(b,c,d) (b ^ c ^ d)


#define LOADSCHEDULE(i, w, block)\
        w[i] = __builtin_bswap32(*(reinterpret_cast<unsigned int *>(block+i*sizeof(unsigned int))));

#define SCHEDULE(i, w) \
        w[i] = ROL((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1);

#define ROUND0s(a,b,c,d,e,i,w,block) \
        LOADSCHEDULE(i, w, block)\
        ROUNDTAIL(a, b, e, F1(b, c, d), i, 0x5A827999, w)

#define ROUND0(a,b,c,d,e,i,w) \
        SCHEDULE(i, w) \
        ROUNDTAIL(a, b, e, F1(b, c, d), i, 0x5A827999, w)

#define ROUND1(a,b,c,d,e,i,w) \
        SCHEDULE(i, w) \
        ROUNDTAIL(a, b, e, F2(b, c, d), i, 0x6ED9EBA1, w)

#define ROUND2(a,b,c,d,e,i,w) \
        SCHEDULE(i, w) \
        ROUNDTAIL(a, b, e, F3(b, c, d), i, 0x8F1BBCDC, w)

#define ROUND3(a,b,c,d,e,i,w) \
        SCHEDULE(i, w) \
        ROUNDTAIL(a, b, e, F4(b, c, d), i, 0xCA62C1D6, w)

void ZIPTDESCrackerCPU::sha1(const uint8_t* msg,unsigned int len,uint8_t* output){
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;
    
    uint32_t chunks = ((len+9)/64)+1;
    uint32_t padSpace = 64-(len%64);
    uint32_t padInChunk;
    bool longPad;
    
    uint8_t msg_pad[64];
    uint32_t w[80] = {0};
    
    if(padSpace < 9){
        padInChunk = chunks-2;
        longPad = true;
    }else{
        padInChunk = chunks-1;
        longPad = false;
    }
    
    for(uint32_t chunk = 0;chunk<chunks;chunk++){
        
        if(chunk < padInChunk){
            ::memcpy(msg_pad,msg+chunk*64,64);
        }else if(chunk == padInChunk){
            uint32_t padStart = len%64;
            ::memcpy(msg_pad,msg+chunk*64,padStart);
            msg_pad[padStart] = 0x80;
            if(longPad){
                // pad in last two chunks
                for(uint32_t i = padStart+1;i<64;i++){
                    msg_pad[i] = 0;
                }
            }else{
                // pad in last chunk
                for(uint32_t i = padStart+1;i<64-4;i++){
                    msg_pad[i] = 0;
                }
                uint64_t bit_len = len*8;
                msg_pad[60] = (bit_len >> 24) & 0xFF;
                msg_pad[61] = (bit_len >> 16) & 0xFF;
                msg_pad[62] = (bit_len >> 8) & 0xFF;
                msg_pad[63] = bit_len & 0xFF;
            }
        }else{
            for(uint32_t i = 0;i<64-4;i++){
                    msg_pad[i] = 0;
            }
            uint64_t bit_len = len*8;
            msg_pad[60] = (bit_len >> 24) & 0xFF;
            msg_pad[61] = (bit_len >> 16) & 0xFF;
            msg_pad[62] = (bit_len >> 8) & 0xFF;
            msg_pad[63] = bit_len & 0xFF;
        }
        
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;

        
	ROUND0s(a, b, c, d, e,  0, w, msg_pad)
	ROUND0s(e, a, b, c, d,  1, w, msg_pad)
	ROUND0s(d, e, a, b, c,  2, w, msg_pad)
	ROUND0s(c, d, e, a, b,  3, w, msg_pad)
	ROUND0s(b, c, d, e, a,  4, w, msg_pad)
	ROUND0s(a, b, c, d, e,  5, w, msg_pad)
	ROUND0s(e, a, b, c, d,  6, w, msg_pad)
	ROUND0s(d, e, a, b, c,  7, w, msg_pad)
	ROUND0s(c, d, e, a, b,  8, w, msg_pad)
	ROUND0s(b, c, d, e, a,  9, w, msg_pad)
	ROUND0s(a, b, c, d, e, 10, w, msg_pad)
	ROUND0s(e, a, b, c, d, 11, w, msg_pad)
	ROUND0s(d, e, a, b, c, 12, w, msg_pad)
	ROUND0s(c, d, e, a, b, 13, w, msg_pad)
	ROUND0s(b, c, d, e, a, 14, w, msg_pad)
	ROUND0s(a, b, c, d, e, 15, w, msg_pad)
	ROUND0(e, a, b, c, d, 16, w)
	ROUND0(d, e, a, b, c, 17, w)
	ROUND0(c, d, e, a, b, 18, w)
	ROUND0(b, c, d, e, a, 19, w)
	ROUND1(a, b, c, d, e, 20, w)
	ROUND1(e, a, b, c, d, 21, w)
	ROUND1(d, e, a, b, c, 22, w)
	ROUND1(c, d, e, a, b, 23, w)
	ROUND1(b, c, d, e, a, 24, w)
	ROUND1(a, b, c, d, e, 25, w)
	ROUND1(e, a, b, c, d, 26, w)
	ROUND1(d, e, a, b, c, 27, w)
	ROUND1(c, d, e, a, b, 28, w)
	ROUND1(b, c, d, e, a, 29, w)
	ROUND1(a, b, c, d, e, 30, w)
	ROUND1(e, a, b, c, d, 31, w)
	ROUND1(d, e, a, b, c, 32, w)
	ROUND1(c, d, e, a, b, 33, w)
	ROUND1(b, c, d, e, a, 34, w)
	ROUND1(a, b, c, d, e, 35, w)
	ROUND1(e, a, b, c, d, 36, w)
	ROUND1(d, e, a, b, c, 37, w)
	ROUND1(c, d, e, a, b, 38, w)
	ROUND1(b, c, d, e, a, 39, w)
	ROUND2(a, b, c, d, e, 40, w)
	ROUND2(e, a, b, c, d, 41, w)
	ROUND2(d, e, a, b, c, 42, w)
	ROUND2(c, d, e, a, b, 43, w)
	ROUND2(b, c, d, e, a, 44, w)
	ROUND2(a, b, c, d, e, 45, w)
	ROUND2(e, a, b, c, d, 46, w)
	ROUND2(d, e, a, b, c, 47, w)
	ROUND2(c, d, e, a, b, 48, w)
	ROUND2(b, c, d, e, a, 49, w)
	ROUND2(a, b, c, d, e, 50, w)
	ROUND2(e, a, b, c, d, 51, w)
	ROUND2(d, e, a, b, c, 52, w)
	ROUND2(c, d, e, a, b, 53, w)
	ROUND2(b, c, d, e, a, 54, w)
	ROUND2(a, b, c, d, e, 55, w)
	ROUND2(e, a, b, c, d, 56, w)
	ROUND2(d, e, a, b, c, 57, w)
	ROUND2(c, d, e, a, b, 58, w)
	ROUND2(b, c, d, e, a, 59, w)
	ROUND3(a, b, c, d, e, 60, w)
	ROUND3(e, a, b, c, d, 61, w)
	ROUND3(d, e, a, b, c, 62, w)
	ROUND3(c, d, e, a, b, 63, w)
	ROUND3(b, c, d, e, a, 64, w)
	ROUND3(a, b, c, d, e, 65, w)
	ROUND3(e, a, b, c, d, 66, w)
	ROUND3(d, e, a, b, c, 67, w)
	ROUND3(c, d, e, a, b, 68, w)
	ROUND3(b, c, d, e, a, 69, w)
	ROUND3(a, b, c, d, e, 70, w)
	ROUND3(e, a, b, c, d, 71, w)
	ROUND3(d, e, a, b, c, 72, w)
	ROUND3(c, d, e, a, b, 73, w)
	ROUND3(b, c, d, e, a, 74, w)
	ROUND3(a, b, c, d, e, 75, w)
	ROUND3(e, a, b, c, d, 76, w)
	ROUND3(d, e, a, b, c, 77, w)
	ROUND3(c, d, e, a, b, 78, w)
	ROUND3(b, c, d, e, a, 79, w)
        
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }
    
    output[0] = h0 >> 24;
    output[1] = (h0 >> 16) & 0xFF;
    output[2] = (h0 >> 8) & 0xFF;
    output[3] = h0 & 0xFF;
    
    output[4] = h1 >> 24;
    output[5] = (h1 >> 16) & 0xFF;
    output[6] = (h1 >> 8) & 0xFF;
    output[7] = h1 & 0xFF;
    
    output[8] = h2 >> 24;
    output[9] = (h2 >> 16) & 0xFF;
    output[10] = (h2 >> 8) & 0xFF;
    output[11] = h2 & 0xFF;
    
    output[12] = h3 >> 24;
    output[13] = (h3 >> 16) & 0xFF;
    output[14] = (h3 >> 8) & 0xFF;
    output[15] = h3 & 0xFF;
    
    output[16] = h4 >> 24;
    output[17] = (h4 >> 16) & 0xFF;
    output[18] = (h4 >> 8) & 0xFF;
    output[19] = h4 & 0xFF;
    
}

void ZIPTDESCrackerCPU::sha1_fast(const uint8_t* msg,unsigned int len,uint8_t* output){
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;
    
    uint32_t chunks = ((len+9)/64)+1;
    
    uint8_t msg_pad_space[2*64] = {0};
    uint8_t *msg_pad = msg_pad_space;
    uint32_t w[80] = {0};
    
    uint8_t pos = 62;
    
    if(len > 2*64-9){
        return;
    }
    memcpy(msg_pad,msg,len*sizeof(char));
    msg_pad[len] = 0x80;
    if(len > 56)
        pos = 126;
    
    unsigned long long int bit_len = len*8;
    msg_pad[pos++] = (bit_len >> 8) & 0xFF;
    msg_pad[pos] = bit_len & 0xFF;
    
    for(uint32_t chunk = 0;chunk<chunks;chunk++){
        unsigned int register a = h0;
        unsigned int register b = h1;
        unsigned int register c = h2;
        unsigned int register d = h3;
        unsigned int register e = h4;

        
    ROUND0s(a, b, c, d, e,  0, w, msg_pad)
	ROUND0s(e, a, b, c, d,  1, w, msg_pad)
	ROUND0s(d, e, a, b, c,  2, w, msg_pad)
	ROUND0s(c, d, e, a, b,  3, w, msg_pad)
	ROUND0s(b, c, d, e, a,  4, w, msg_pad)
	ROUND0s(a, b, c, d, e,  5, w, msg_pad)
	ROUND0s(e, a, b, c, d,  6, w, msg_pad)
	ROUND0s(d, e, a, b, c,  7, w, msg_pad)
	ROUND0s(c, d, e, a, b,  8, w, msg_pad)
	ROUND0s(b, c, d, e, a,  9, w, msg_pad)
	ROUND0s(a, b, c, d, e, 10, w, msg_pad)
	ROUND0s(e, a, b, c, d, 11, w, msg_pad)
	ROUND0s(d, e, a, b, c, 12, w, msg_pad)
	ROUND0s(c, d, e, a, b, 13, w, msg_pad)
	ROUND0s(b, c, d, e, a, 14, w, msg_pad)
	ROUND0s(a, b, c, d, e, 15, w, msg_pad)
	ROUND0(e, a, b, c, d, 16, w)
	ROUND0(d, e, a, b, c, 17, w)
	ROUND0(c, d, e, a, b, 18, w)
	ROUND0(b, c, d, e, a, 19, w)
	ROUND1(a, b, c, d, e, 20, w)
	ROUND1(e, a, b, c, d, 21, w)
	ROUND1(d, e, a, b, c, 22, w)
	ROUND1(c, d, e, a, b, 23, w)
	ROUND1(b, c, d, e, a, 24, w)
	ROUND1(a, b, c, d, e, 25, w)
	ROUND1(e, a, b, c, d, 26, w)
	ROUND1(d, e, a, b, c, 27, w)
	ROUND1(c, d, e, a, b, 28, w)
	ROUND1(b, c, d, e, a, 29, w)
	ROUND1(a, b, c, d, e, 30, w)
	ROUND1(e, a, b, c, d, 31, w)
	ROUND1(d, e, a, b, c, 32, w)
	ROUND1(c, d, e, a, b, 33, w)
	ROUND1(b, c, d, e, a, 34, w)
	ROUND1(a, b, c, d, e, 35, w)
	ROUND1(e, a, b, c, d, 36, w)
	ROUND1(d, e, a, b, c, 37, w)
	ROUND1(c, d, e, a, b, 38, w)
	ROUND1(b, c, d, e, a, 39, w)
	ROUND2(a, b, c, d, e, 40, w)
	ROUND2(e, a, b, c, d, 41, w)
	ROUND2(d, e, a, b, c, 42, w)
	ROUND2(c, d, e, a, b, 43, w)
	ROUND2(b, c, d, e, a, 44, w)
	ROUND2(a, b, c, d, e, 45, w)
	ROUND2(e, a, b, c, d, 46, w)
	ROUND2(d, e, a, b, c, 47, w)
	ROUND2(c, d, e, a, b, 48, w)
	ROUND2(b, c, d, e, a, 49, w)
	ROUND2(a, b, c, d, e, 50, w)
	ROUND2(e, a, b, c, d, 51, w)
	ROUND2(d, e, a, b, c, 52, w)
	ROUND2(c, d, e, a, b, 53, w)
	ROUND2(b, c, d, e, a, 54, w)
	ROUND2(a, b, c, d, e, 55, w)
	ROUND2(e, a, b, c, d, 56, w)
	ROUND2(d, e, a, b, c, 57, w)
	ROUND2(c, d, e, a, b, 58, w)
	ROUND2(b, c, d, e, a, 59, w)
	ROUND3(a, b, c, d, e, 60, w)
	ROUND3(e, a, b, c, d, 61, w)
	ROUND3(d, e, a, b, c, 62, w)
	ROUND3(c, d, e, a, b, 63, w)
	ROUND3(b, c, d, e, a, 64, w)
	ROUND3(a, b, c, d, e, 65, w)
	ROUND3(e, a, b, c, d, 66, w)
	ROUND3(d, e, a, b, c, 67, w)
	ROUND3(c, d, e, a, b, 68, w)
	ROUND3(b, c, d, e, a, 69, w)
	ROUND3(a, b, c, d, e, 70, w)
	ROUND3(e, a, b, c, d, 71, w)
	ROUND3(d, e, a, b, c, 72, w)
	ROUND3(c, d, e, a, b, 73, w)
	ROUND3(b, c, d, e, a, 74, w)
	ROUND3(a, b, c, d, e, 75, w)
	ROUND3(e, a, b, c, d, 76, w)
	ROUND3(d, e, a, b, c, 77, w)
	ROUND3(c, d, e, a, b, 78, w)
	ROUND3(b, c, d, e, a, 79, w)
        
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        msg_pad += 64;
    }
    
    output[0] = h0 >> 24;
    output[1] = (h0 >> 16) & 0xFF;
    output[2] = (h0 >> 8) & 0xFF;
    output[3] = h0 & 0xFF;
    
    output[4] = h1 >> 24;
    output[5] = (h1 >> 16) & 0xFF;
    output[6] = (h1 >> 8) & 0xFF;
    output[7] = h1 & 0xFF;
    
    output[8] = h2 >> 24;
    output[9] = (h2 >> 16) & 0xFF;
    output[10] = (h2 >> 8) & 0xFF;
    output[11] = h2 & 0xFF;
    
    output[12] = h3 >> 24;
    output[13] = (h3 >> 16) & 0xFF;
    output[14] = (h3 >> 8) & 0xFF;
    output[15] = h3 & 0xFF;
    
    output[16] = h4 >> 24;
    output[17] = (h4 >> 16) & 0xFF;
    output[18] = (h4 >> 8) & 0xFF;
    output[19] = h4 & 0xFF;
    
}

void ZIPTDESCrackerCPU::hmac_sha1(const uint8_t* msg,unsigned int msgLen, const uint8_t* key,unsigned int keyLen,uint8_t* output){
    uint8_t *key_pad = new unsigned char[64+msgLen];
    ::memset(key_pad,0x36,64*sizeof(char));
    for(uint8_t i = 0;i<keyLen; i++){
        key_pad[i] ^= key[i];
    }
    
    memcpy(key_pad+64,msg,msgLen*sizeof(char));
    sha1(key_pad,64+msgLen,output);
    memset(key_pad,0x5C,64*sizeof(char));
    for(uint8_t i = 0;i<keyLen; i++){
        key_pad[i] ^= key[i];
    }
    
    memcpy(key_pad+64,output,20*sizeof(char));
    sha1_fast(key_pad,84,output);
    delete[] key_pad;
}

void ZIPTDESCrackerCPU::hmac_sha1_fast(const uint8_t* msg,unsigned int msgLen, const uint8_t* key,unsigned int keyLen,uint8_t* output){
    unsigned char key_pad[256];
    memset(key_pad,0x36,64*sizeof(char));
    for(uint8_t i = 0;i<keyLen; i++){
        key_pad[i] ^= key[i];
    }
    memcpy(key_pad+64,msg,msgLen*sizeof(char));
    sha1_fast(key_pad,64+msgLen,output);

    memset(key_pad,0x5C,64*sizeof(char));
    for(uint8_t i = 0;i<keyLen; i++){
        key_pad[i] ^= key[i];
    }
    memcpy(key_pad+64,output,20*sizeof(char));
    sha1_fast(key_pad,84,output);
}

#define ADD_XOR(res, in) \
        for (int i = 0;i<20;i++) \
             res[i] ^= in[i];
        
        

void ZIPTDESCrackerCPU::pbkdf2_sha1(const uint8_t* pass, unsigned int passLen, const uint8_t* in_salt,unsigned int saltLen, unsigned int iterations, unsigned int dkLen, uint8_t* output){
    if(saltLen>16)
        return;

    int l = dkLen / 20;
    int l_rem = dkLen % 20;
    if (l_rem > 0)
        l++;

    
    uint8_t prevU[20];
    uint8_t Fres[20];
    uint8_t T[80] = {0};
    
    
    for(int i=1;i<=l;i++){
        memset(Fres,0,20*sizeof(uint8_t));
        memcpy(prevU,in_salt,saltLen*sizeof(char));
        *((unsigned int*)(prevU+saltLen)) = __builtin_bswap32(i);
        hmac_sha1_fast(prevU,saltLen+4,pass,passLen,prevU);
        ADD_XOR(Fres,prevU);
        for(uint32_t c=1;c<iterations;c++){
            hmac_sha1_fast(prevU,20,pass,passLen,prevU);
            ADD_XOR(Fres,prevU);
        }
        memcpy(T+(i-1)*20,Fres,20*sizeof(uint8_t));
    }
    memcpy(output,T,dkLen*sizeof(uint8_t));
    
    
}


void ZIPTDESCrackerCPU::pbkdf2_sha1_zip_aes256(const uint8_t* pass, unsigned int passLen, const uint8_t* in_salt, uint8_t* output){

    uint8_t prevU[20];
    uint8_t Fres[20];    
    

    memset(Fres,0,20*sizeof(uint8_t));
    memcpy(prevU,in_salt,16*sizeof(char));
    *((uint32_t*)(prevU+16)) = 0x04000000;

    
    hmac_sha1_fast(prevU,20,pass,passLen,prevU);
    
    ADD_XOR(Fres,prevU);
    for(int c=1;c<1000;c++){
        hmac_sha1_fast(prevU,20,pass,passLen,prevU);
        ADD_XOR(Fres,prevU);
    }
    memcpy(output,Fres+4,2*sizeof(uint8_t));  
}

void ZIPTDESCrackerCPU::pbkdf2_sha1_zip_aes192(const uint8_t* pass, unsigned int passLen, const uint8_t* in_salt, uint8_t* output){

    uint8_t prevU[20];
    uint8_t Fres[20];    
    

    memset(Fres,0,20*sizeof(uint8_t));
    memcpy(prevU,in_salt,12*sizeof(char));
    *((uint32_t*)(prevU+12)) = 0x03000000;
    hmac_sha1_fast(prevU,12+4,pass,passLen,prevU);
    ADD_XOR(Fres,prevU);
    for(int c=1;c<1000;c++){
        hmac_sha1_fast(prevU,20,pass,passLen,prevU);
        ADD_XOR(Fres,prevU);
    }
    memcpy(output,Fres+8,2*sizeof(uint8_t)); 
}

void ZIPTDESCrackerCPU::pbkdf2_sha1_zip_aes128(const uint8_t* pass, unsigned int passLen, const uint8_t* in_salt, uint8_t* output){

    uint8_t prevU[20];
    uint8_t Fres[20];    
    

    memset(Fres,0,20*sizeof(uint8_t));
    memcpy(prevU,in_salt,8*sizeof(char));
    *((uint32_t*)(prevU+8)) = 0x02000000;
    hmac_sha1_fast(prevU,8+4,pass,passLen,prevU);
    ADD_XOR(Fres,prevU);
    for(int c=1;c<1000;c++){
        hmac_sha1_fast(prevU,20,pass,passLen,prevU);
        ADD_XOR(Fres,prevU);
    }
    memcpy(output,Fres+12,2*sizeof(uint8_t)); 
}
