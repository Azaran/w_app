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
#include "sevenz_aes_lib.cl"
#include "sevenz_sha_lib.cl"

void hash(uchar* input, uint inputlen, uchar* output){

    CSha256 sha;
    Sha256_Init(&sha);
    
    uchar *ctr = password + inputlen - 8;
    ulong numRounds = 1 << 19;
    while (numRounds--)
    {
	Sha256_Update(&sha, password, passSize);
	for (ushort i = 0; i < 8; i++)
	    if (++(ctr[i]) != 0)
		break;
    }
    Sha256_Final(&sha, output);
}
#define MAX_PASS_SIZE 32
void convertKey(const uchar* pass, uint passlen, uchar *key){
    uint passSize; 
    
    passSize = 2*passlen + 8; 
    
    uint i;
    #pragma unroll
    for (i=0; i < passlen; i++){
	key[i*2] = pass[i];
	key[i*2+1] = 0;
    }
    #pragma unroll
    for (i = i*2+1; i<passSize; i++)
	key[i] = 0;
}

kernel void sevenz_aes_kernel(\
        global uchar* passwords,\
        uchar pass_len,\
        global uchar *found_flag,\
        global uint *found_vector,\
        constant uchar *salt,\
        constant uchar *verifier\
        ) {
    int id = get_global_id(0);
    
    uchar my_pass_len = passwords[id*pass_len];
    uchar pass_buffer[MAX_PASS_SIZE];
    uchar raw_block[16];
    uchar key[32]; 
    uchar extended_pass[MAX_PASS_SIZE*2+8];
    
    ELzmaStatus status;
    SRes decode;
    uint aes[AES_NUM_IVMRK_WORDS+3];
    
    for(int i = 0; i<my_pass_len; i++){
        pass_buffer[i] = passwords[id*pass_len+1+i];
    }
    
    convertKey(pass_buffer, my_pass_len, extended_pass);
    hash(extended_pass, key);
    AesCbc_Init(aes+offset, iv);
    Aes_SetKey_Dec(aes+offset+4, key, AES_KEY_SIZE);
    g_AesCbc_Decode(aes+offset, first_block, 1); 
    
    
    if (first_block[0] != 0)
        return;
    
    *found_flag = 1;
    uint big_pos = id/32;
    uint small_pos = id%32;
    uint val = 0x80000000 >> small_pos;
    atomic_or(found_vector+big_pos,val);
}
