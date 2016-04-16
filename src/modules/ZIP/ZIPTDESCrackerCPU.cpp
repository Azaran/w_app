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

// #include "ZIPTDESCrackerCPU.h"
// #include <deque>
// #include <string.h>
// #include <iostream>
// #include "crc.h"
// 
// #include <cryptopp/cryptlib.h>
// using CryptoPP::Exception;
// 
// #include <cryptopp/hex.h>
// using CryptoPP::HexEncoder;
// using CryptoPP::HexDecoder;
// 
// #include <cryptopp/filters.h>
// using CryptoPP::StringSink;
// using CryptoPP::StringSource;
// using CryptoPP::StreamTransformationFilter;
// 
// #include <cryptopp/des.h>
// using CryptoPP::DES_EDE3;
// 
// #include <cryptopp/modes.h>
// using CryptoPP::CBC_Mode;
// 
// #include <cryptopp/secblock.h>
// using CryptoPP::SecByteBlock;
// 
// using namespace std;
// 
// ZIPTDESCrackerCPU::ZIPTDESCrackerCPU(std::vector<ZIPInitData> *data):data(data) {
//     for(int i = 0; i < this->data->size(); i++){
//         if((*this->data)[i].dataLen > 0){
//             check_data = (*(this->data))[i];
//             break;
//         }
//     }
//     rdData = new uint8_t [check_data.erdSize];
//     tempKey = new uint8_t [check_data.ivSize + check_data.erdSize];
//     vData = new uint8_t [check_data.encSize];
// 	
// }
// 
// ZIPTDESCrackerCPU::ZIPTDESCrackerCPU(const ZIPTDESCrackerCPU &orig){}
// 
// ZIPTDESCrackerCPU::~ZIPTDESCrackerCPU() {
// }
// 
// CheckResult ZIPTDESCrackerCPU::checkPassword(const std::string* pass) {
//     
//     uint32_t crc = 0;
//     
//     derive(reinterpret_cast<const uint8_t*>(pass->c_str()), pass->length(), (uint8_t*)key);
// 
//     
//     tdesDecrypt(key, check_data.erdData, check_data.erdSize, rdData); 
//     
//     cout << "ivData: " << endl;
//     for (int i=0; i < 8; i++){
//         cout << hex << setw(2) << setfill('0') << (int)check_data.ivData[i] << " ";
//     }
//     cout << endl;
//     
//     cout << "key1: " << endl;
//     for (int i=0; i < 21; i++){
//         cout << hex << setw(2) << setfill('0') << (int)key[i] << " ";
//     }
//     cout << endl;
//     cout << "erdData: " << endl;
//     for (int i=0; i < check_data.erdSize; i++){
//         cout << hex << setw(2) << setfill('0') << (int)check_data.erdData[i] << " ";
//     }
//     cout << endl;
//     
//     cout << "rdData: " << endl;
//     for (int i=0; i < check_data.erdSize; i++){
//         cout << hex << setw(2) << setfill('0') << (int)rdData[i] << " ";
//     }
//     cout << endl;
//     memcpy(tempKey, check_data.ivData, check_data.ivSize);
//     memcpy(tempKey+check_data.ivSize, rdData, check_data.erdSize);
// 
//     derive(tempKey, check_data.ivSize+check_data.erdSize, key);   
// 
//     cout << "key: " << endl;
//     for (int i=0; i < 21; i++){
//         cout << hex << setw(2) << setfill('0') << (int)key[i] << " ";
//     }
//     cout << endl;
//     
//     cout << "encData: " << endl;
//     for (int i=0; i < check_data.encSize; i++){
//         cout << hex << setw(2) << setfill('0') << (int)check_data.encData[i] << " ";
//     }
//     cout << endl;
//     
//     tdesDecrypt(key, check_data.encData, check_data.encSize, vData);
//     
//     cout << "vData: " << endl;
//     for (int i=0; i < check_data.encSize; i++){
//         cout << hex << setw(2) << setfill('0') << (int)vData[i] << " ";
//     }
//     cout << endl;
// 
//     crc = crc ^ vData[check_data.encSize-1];
//     crc = crc << 8 ^ vData[check_data.encSize-2];
//     crc = crc << 8 ^ vData[check_data.encSize-3];
//     crc = crc << 8 ^ vData[check_data.encSize-4];
//     
//     cout << "crc: " << crc << endl;
//     cout << "crc: " << crc32(0, vData, check_data.encSize-4) << endl;
//     exit(0);
//     if (crc == crc32(0, vData, check_data.encSize-4)){
//         return CR_PASSWORD_MATCH;
//     }
//     
//     return CR_PASSWORD_WRONG;
// }
// 
// #define ROL(x, n) ((x << n) | ((x) >> (sizeof(n)*8 - n)))
// 
// #define ROUNDTAIL(a,b,e,f,i,k,w)  \
// 	e += ROL(a,5) + f + k + w[i];  \
// 	b = ROL(b,30);
// 
// #define F1(b,c,d) (d ^ (b & (c ^ d)))
// #define F2(b,c,d) (b ^ c ^ d)
// #define F3(b,c,d) ((b & c) ^ (b & d) ^ (c & d))
// #define F4(b,c,d) (b ^ c ^ d)
// 
// 
// #define LOADSCHEDULE(i, w, block)\
//         w[i] = __builtin_bswap32(*(reinterpret_cast<unsigned int *>(block+i*sizeof(unsigned int))));
// 
// #define SCHEDULE(i, w) \
//         w[i] = ROL((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1);
// 
// #define ROUND0s(a,b,c,d,e,i,w,block) \
//         LOADSCHEDULE(i, w, block)\
//         ROUNDTAIL(a, b, e, F1(b, c, d), i, 0x5A827999, w)
// 
// #define ROUND0(a,b,c,d,e,i,w) \
//         SCHEDULE(i, w) \
//         ROUNDTAIL(a, b, e, F1(b, c, d), i, 0x5A827999, w)
// 
// #define ROUND1(a,b,c,d,e,i,w) \
//         SCHEDULE(i, w) \
//         ROUNDTAIL(a, b, e, F2(b, c, d), i, 0x6ED9EBA1, w)
// 
// #define ROUND2(a,b,c,d,e,i,w) \
//         SCHEDULE(i, w) \
//         ROUNDTAIL(a, b, e, F3(b, c, d), i, 0x8F1BBCDC, w)
// 
// #define ROUND3(a,b,c,d,e,i,w) \
//         SCHEDULE(i, w) \
//         ROUNDTAIL(a, b, e, F4(b, c, d), i, 0xCA62C1D6, w)
// 
// void ZIPTDESCrackerCPU::sha1(const uint8_t* msg,unsigned int len,uint8_t* output){
//     uint32_t h0 = 0x67452301;
//     uint32_t h1 = 0xEFCDAB89;
//     uint32_t h2 = 0x98BADCFE;
//     uint32_t h3 = 0x10325476;
//     uint32_t h4 = 0xC3D2E1F0;
//     
//     uint32_t chunks = ((len+9)/64)+1;
//     uint32_t padSpace = 64-(len%64);
//     uint32_t padInChunk;
//     bool longPad;
//     
//     uint8_t msg_pad[64];
//     uint32_t w[80] = {0};
//     
//     if(padSpace < 9){
//         padInChunk = chunks-2;
//         longPad = true;
//     }else{
//         padInChunk = chunks-1;
//         longPad = false;
//     }
//     
//     for(uint32_t chunk = 0;chunk<chunks;chunk++){
//         
//         if(chunk < padInChunk){
//             ::memcpy(msg_pad,msg+chunk*64,64);
//         }else if(chunk == padInChunk){
//             uint32_t padStart = len%64;
//             memcpy(msg_pad,msg+chunk*64,padStart);
//             msg_pad[padStart] = 0x80;
//             if(longPad){
//                 // pad in last two chunks
//                 for(uint32_t i = padStart+1;i<64;i++){
//                     msg_pad[i] = 0;
//                 }
//             }else{
//                 // pad in last chunk
//                 for(uint32_t i = padStart+1;i<64-4;i++){
//                     msg_pad[i] = 0;
//                 }
//                 uint64_t bit_len = len*8;
//                 msg_pad[60] = (bit_len >> 24) & 0xFF;
//                 msg_pad[61] = (bit_len >> 16) & 0xFF;
//                 msg_pad[62] = (bit_len >> 8) & 0xFF;
//                 msg_pad[63] = bit_len & 0xFF;
//             }
//         }else{
//             for(uint32_t i = 0;i<64-4;i++){
//                     msg_pad[i] = 0;
//             }
//             uint64_t bit_len = len*8;
//             msg_pad[60] = (bit_len >> 24) & 0xFF;
//             msg_pad[61] = (bit_len >> 16) & 0xFF;
//             msg_pad[62] = (bit_len >> 8) & 0xFF;
//             msg_pad[63] = bit_len & 0xFF;
//         }
//         
//         uint32_t a = h0;
//         uint32_t b = h1;
//         uint32_t c = h2;
//         uint32_t d = h3;
//         uint32_t e = h4;
// 
//         
// 	ROUND0s(a, b, c, d, e,  0, w, msg_pad)
// 	ROUND0s(e, a, b, c, d,  1, w, msg_pad)
// 	ROUND0s(d, e, a, b, c,  2, w, msg_pad)
// 	ROUND0s(c, d, e, a, b,  3, w, msg_pad)
// 	ROUND0s(b, c, d, e, a,  4, w, msg_pad)
// 	ROUND0s(a, b, c, d, e,  5, w, msg_pad)
// 	ROUND0s(e, a, b, c, d,  6, w, msg_pad)
// 	ROUND0s(d, e, a, b, c,  7, w, msg_pad)
// 	ROUND0s(c, d, e, a, b,  8, w, msg_pad)
// 	ROUND0s(b, c, d, e, a,  9, w, msg_pad)
// 	ROUND0s(a, b, c, d, e, 10, w, msg_pad)
// 	ROUND0s(e, a, b, c, d, 11, w, msg_pad)
// 	ROUND0s(d, e, a, b, c, 12, w, msg_pad)
// 	ROUND0s(c, d, e, a, b, 13, w, msg_pad)
// 	ROUND0s(b, c, d, e, a, 14, w, msg_pad)
// 	ROUND0s(a, b, c, d, e, 15, w, msg_pad)
// 	ROUND0(e, a, b, c, d, 16, w)
// 	ROUND0(d, e, a, b, c, 17, w)
// 	ROUND0(c, d, e, a, b, 18, w)
// 	ROUND0(b, c, d, e, a, 19, w)
// 	ROUND1(a, b, c, d, e, 20, w)
// 	ROUND1(e, a, b, c, d, 21, w)
// 	ROUND1(d, e, a, b, c, 22, w)
// 	ROUND1(c, d, e, a, b, 23, w)
// 	ROUND1(b, c, d, e, a, 24, w)
// 	ROUND1(a, b, c, d, e, 25, w)
// 	ROUND1(e, a, b, c, d, 26, w)
// 	ROUND1(d, e, a, b, c, 27, w)
// 	ROUND1(c, d, e, a, b, 28, w)
// 	ROUND1(b, c, d, e, a, 29, w)
// 	ROUND1(a, b, c, d, e, 30, w)
// 	ROUND1(e, a, b, c, d, 31, w)
// 	ROUND1(d, e, a, b, c, 32, w)
// 	ROUND1(c, d, e, a, b, 33, w)
// 	ROUND1(b, c, d, e, a, 34, w)
// 	ROUND1(a, b, c, d, e, 35, w)
// 	ROUND1(e, a, b, c, d, 36, w)
// 	ROUND1(d, e, a, b, c, 37, w)
// 	ROUND1(c, d, e, a, b, 38, w)
// 	ROUND1(b, c, d, e, a, 39, w)
// 	ROUND2(a, b, c, d, e, 40, w)
// 	ROUND2(e, a, b, c, d, 41, w)
// 	ROUND2(d, e, a, b, c, 42, w)
// 	ROUND2(c, d, e, a, b, 43, w)
// 	ROUND2(b, c, d, e, a, 44, w)
// 	ROUND2(a, b, c, d, e, 45, w)
// 	ROUND2(e, a, b, c, d, 46, w)
// 	ROUND2(d, e, a, b, c, 47, w)
// 	ROUND2(c, d, e, a, b, 48, w)
// 	ROUND2(b, c, d, e, a, 49, w)
// 	ROUND2(a, b, c, d, e, 50, w)
// 	ROUND2(e, a, b, c, d, 51, w)
// 	ROUND2(d, e, a, b, c, 52, w)
// 	ROUND2(c, d, e, a, b, 53, w)
// 	ROUND2(b, c, d, e, a, 54, w)
// 	ROUND2(a, b, c, d, e, 55, w)
// 	ROUND2(e, a, b, c, d, 56, w)
// 	ROUND2(d, e, a, b, c, 57, w)
// 	ROUND2(c, d, e, a, b, 58, w)
// 	ROUND2(b, c, d, e, a, 59, w)
// 	ROUND3(a, b, c, d, e, 60, w)
// 	ROUND3(e, a, b, c, d, 61, w)
// 	ROUND3(d, e, a, b, c, 62, w)
// 	ROUND3(c, d, e, a, b, 63, w)
// 	ROUND3(b, c, d, e, a, 64, w)
// 	ROUND3(a, b, c, d, e, 65, w)
// 	ROUND3(e, a, b, c, d, 66, w)
// 	ROUND3(d, e, a, b, c, 67, w)
// 	ROUND3(c, d, e, a, b, 68, w)
// 	ROUND3(b, c, d, e, a, 69, w)
// 	ROUND3(a, b, c, d, e, 70, w)
// 	ROUND3(e, a, b, c, d, 71, w)
// 	ROUND3(d, e, a, b, c, 72, w)
// 	ROUND3(c, d, e, a, b, 73, w)
// 	ROUND3(b, c, d, e, a, 74, w)
// 	ROUND3(a, b, c, d, e, 75, w)
// 	ROUND3(e, a, b, c, d, 76, w)
// 	ROUND3(d, e, a, b, c, 77, w)
// 	ROUND3(c, d, e, a, b, 78, w)
// 	ROUND3(b, c, d, e, a, 79, w)
//         
//         h0 += a;
//         h1 += b;
//         h2 += c;
//         h3 += d;
//         h4 += e;
//     }
//     
//     output[0] = h0 >> 24;
//     output[1] = (h0 >> 16) & 0xFF;
//     output[2] = (h0 >> 8) & 0xFF;
//     output[3] = h0 & 0xFF;
//     
//     output[4] = h1 >> 24;
//     output[5] = (h1 >> 16) & 0xFF;
//     output[6] = (h1 >> 8) & 0xFF;
//     output[7] = h1 & 0xFF;
//     
//     output[8] = h2 >> 24;
//     output[9] = (h2 >> 16) & 0xFF;
//     output[10] = (h2 >> 8) & 0xFF;
//     output[11] = h2 & 0xFF;
//     
//     output[12] = h3 >> 24;
//     output[13] = (h3 >> 16) & 0xFF;
//     output[14] = (h3 >> 8) & 0xFF;
//     output[15] = h3 & 0xFF;
//     
//     output[16] = h4 >> 24;
//     output[17] = (h4 >> 16) & 0xFF;
//     output[18] = (h4 >> 8) & 0xFF;
//     output[19] = h4 & 0xFF;
//     
// }
// 
// void ZIPTDESCrackerCPU::derive_key(const uint8_t* hash, uint8_t key, uint8_t* output){
//    
//     uint8_t key_pad[64];
//     memset(key_pad,key,64);
// 
//     for(uint8_t i = 0;i<20; i++)
//         key_pad[i] ^= hash[i];
// 
//     sha1(key_pad,64,output);
// }
// 
// void ZIPTDESCrackerCPU::derive(const uint8_t* pass, unsigned int passLen, uint8_t* output){
// 
//     uint8_t passHash[20];
//     uint8_t temp[40];
//    
//     ::memset(passHash,0x00,20);
//     sha1(pass,passLen,passHash);
//     derive_key((uint8_t*)passHash, 0x36 , (uint8_t*)temp);
//     derive_key((uint8_t*)passHash, 0x5c, (uint8_t*)(temp+20));
//     
//    // cout << "key: " << endl;
//    // for (int i=0; i < 32; i++){
//    //     if (i %8 == 0 && i > 0)
//    //         cout << endl;
//    //     uint8_t a = (int)temp[i];
//    //     cout << bitset<8>(a) << " ";
//    // }
//    // cout << endl;
//     memcpy(output, temp, 32); 
// }
// 
// void ZIPTDESCrackerCPU::prepareKey(uint8_t *key, uint8_t *output){
//     uint8_t mask = 0xfe, cmask=0x0;
//     uint8_t ke2, carry = 0;
//     for (int i = 1; i < 9; i++,(*key++)){
// 
// 	ke2 = ((carry << 8-(i-1)) + ((*key) >> i-1)) >> 1 << 1;
// 	(*output++) = ke2;
// 	
// 	cmask = (cmask << 1) + 1;
// 	carry = (*key) & cmask;
// 	
// //	cout << "p: " << bitset<8>((*key)) << endl;
// //	cout << "m: " << bitset<8>(cmask) << endl;
// //	cout << "c: " << bitset<8>(carry) << endl;
// //	cout << "k: " << bitset<8>(ke2) << endl;
// //	cout << "-------------------" << endl;
//     }
// }
// 
// void ZIPTDESCrackerCPU::tdesDecrypt(uint8_t *key, uint8_t *cipher, uint32_t cipherLen, uint8_t *output){
//     
//     string scipher((char*)cipher), recovered;
// 
//     CBC_Mode< DES_EDE3 >::Decryption d;
//     d.SetKeyWithIV(key, DES_EDE3::DEFAULT_KEYLENGTH, check_data.ivData);
//     
//     // The StreamTransformationFilter removes
//     //  padding as required.
//     StringSource s(cipher, true, 
// 	    new StreamTransformationFilter(d,
// 		new StringSink(recovered)
// 		) // StreamTransformationFilter
// 	    ); // StringSource
// 
//     memcpy(output, recovered.c_str(), recovered.length());
// }
