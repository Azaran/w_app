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

#pragma OPENCL EXTENSION cl_amd_printf : enable 



/***************************************************************************
 * This code is based on public domain Szymon Stefanek AES implementation: *
 * http://www.pragmaware.net/software/rijndael/index.php                   *
 *                                                                         *
 * Dynamic tables generation is based on the Brian Gladman work:           *
 * http://fp.gladman.plus.com/cryptography_technology/rijndael             *
 ***************************************************************************/
#define _MAX_KEY_COLUMNS (256/32)
#define _MAX_ROUNDS      14
#define MAX_IV_SIZE      16

typedef struct {
    bool     CBCMode;
    int      m_uRounds;
    uchar     m_initVector[MAX_IV_SIZE];
    uchar     m_expandedKey[_MAX_ROUNDS+1][4][4];
} aes_context;

static uchar S[256],S5[256],rcon[30];
static uchar T1[256][4],T2[256][4],T3[256][4],T4[256][4];
static uchar T5[256][4],T6[256][4],T7[256][4],T8[256][4];
static uchar U1[256][4],U2[256][4],U3[256][4],U4[256][4];

inline void Xor128_2(void *dest,const void *arg1,const void *arg2){
    #pragma unroll
    for (int I=0;I<16;I++)
	((uchar*)dest)[I]=((uchar*)arg1)[I]^((uchar*)arg2)[I];
}
inline void Xor128_2_global(void *dest,global void *arg1,const void *arg2){
    #pragma unroll
    for (int I=0;I<16;I++)
	((uchar*)dest)[I]=((global uchar*)arg1)[I]^((uchar*)arg2)[I];
}

inline void Xor128_4(uchar *dest,const uchar *arg1,const uchar *arg2,
	const uchar *arg3,const uchar *arg4){
    #pragma unroll
    for (int I=0;I<4;I++)
	dest[I]=arg1[I]^arg2[I]^arg3[I]^arg4[I];
}

inline void Copy128(local uchar *dest, uchar *src){
    #pragma unroll
    for (int I=0;I<16;I++)
	dest[I]=src[I];
}
inline void Copy128_global(uchar *dest,global uchar *src){
    #pragma unroll
    for (int I=0;I<16;I++)
	dest[I]=src[I];
}



  
void blockDecrypt(aes_context *aes, global uchar *input, uint inputLen, local uchar *outBuffer)
{
  if (inputLen <= 0)
    return;

  size_t numBlocks=inputLen/16;

  uchar block[16], iv[4][4];
  //memcpy(iv,aes->m_initVector,16); 
  #pragma unroll
  for(int i = 0; i < 4; i++)
      for(int j = 0; j < 4; j++)
	  iv[i][j] = aes->m_initVector[i*4+j];

  for (size_t i = numBlocks; i > 0; i--)
  {
    uchar temp[4][4];
    
    Xor128_2_global(temp,input,aes->m_expandedKey[aes->m_uRounds]);

    Xor128_4(block,   T5[temp[0][0]],T6[temp[3][1]],T7[temp[2][2]],T8[temp[1][3]]);
    Xor128_4(block+4, T5[temp[1][0]],T6[temp[0][1]],T7[temp[3][2]],T8[temp[2][3]]);
    Xor128_4(block+8, T5[temp[2][0]],T6[temp[1][1]],T7[temp[0][2]],T8[temp[3][3]]);
    Xor128_4(block+12,T5[temp[3][0]],T6[temp[2][1]],T7[temp[1][2]],T8[temp[0][3]]);

    for(int r = aes->m_uRounds-1; r > 1; r--)
    {
      Xor128_2(temp,block,aes->m_expandedKey[r]);
      Xor128_4(block,   T5[temp[0][0]],T6[temp[3][1]],T7[temp[2][2]],T8[temp[1][3]]);
      Xor128_4(block+4, T5[temp[1][0]],T6[temp[0][1]],T7[temp[3][2]],T8[temp[2][3]]);
      Xor128_4(block+8, T5[temp[2][0]],T6[temp[1][1]],T7[temp[0][2]],T8[temp[3][3]]);
      Xor128_4(block+12,T5[temp[3][0]],T6[temp[2][1]],T7[temp[1][2]],T8[temp[0][3]]);
    }
   
    Xor128_2(temp,block,aes->m_expandedKey[1]);
    block[ 0] = S5[temp[0][0]];
    block[ 1] = S5[temp[3][1]];
    block[ 2] = S5[temp[2][2]];
    block[ 3] = S5[temp[1][3]];
    block[ 4] = S5[temp[1][0]];
    block[ 5] = S5[temp[0][1]];
    block[ 6] = S5[temp[3][2]];
    block[ 7] = S5[temp[2][3]];
    block[ 8] = S5[temp[2][0]];
    block[ 9] = S5[temp[1][1]];
    block[10] = S5[temp[0][2]];
    block[11] = S5[temp[3][3]];
    block[12] = S5[temp[3][0]];
    block[13] = S5[temp[2][1]];
    block[14] = S5[temp[1][2]];
    block[15] = S5[temp[0][3]];
    Xor128_2(block,block,aes->m_expandedKey[0]);

    if (aes->CBCMode)
      Xor128_2(block,block,iv);

    Copy128_global((uchar*)iv,input);
    Copy128(outBuffer,block);

    input += 16;
    outBuffer += 16;
  }

//  memcpy(aes->m_initVector,iv,16);
  #pragma unroll
  for(int i = 0; i < 16; i++)
    aes->m_initVector[i] = (*iv)[i];

}

void keySched(aes_context *aes,uchar key[_MAX_KEY_COLUMNS][4])
{
  int j,rconpointer = 0;

  // Calculate the necessary round keys
  // The number of calculations depends on keyBits and blockBits
  int uKeyColumns = aes->m_uRounds - 6;

  uchar tempKey[_MAX_KEY_COLUMNS][4];

  // Copy the input key to the temporary key matrix

//  memcpy(tempKey,key,sizeof(tempKey));
  #pragma unroll
  for(int i = 0; i < _MAX_KEY_COLUMNS; i++)
      #pragma unroll
      for(int j = 0; j < 4; j++)
	  tempKey[i][j] = key[i][j];

  int r = 0;
  int t = 0;

  // copy values into round key array
  for(j = 0;(j < uKeyColumns) && (r <= aes->m_uRounds); )
  {
    for(;(j < uKeyColumns) && (t < 4); j++, t++)
      for (int k=0;k<4;k++)
        aes->m_expandedKey[r][t][k]=tempKey[j][k];

    if(t == 4)
    {
      r++;
      t = 0;
    }
  }
    
  while(r <= aes->m_uRounds)
  {
    tempKey[0][0] ^= S[tempKey[uKeyColumns-1][1]];
    tempKey[0][1] ^= S[tempKey[uKeyColumns-1][2]];
    tempKey[0][2] ^= S[tempKey[uKeyColumns-1][3]];
    tempKey[0][3] ^= S[tempKey[uKeyColumns-1][0]];
    tempKey[0][0] ^= rcon[rconpointer++];

    if (uKeyColumns != 8)
      for(j = 1; j < uKeyColumns; j++)
        for (int k=0;k<4;k++)
          tempKey[j][k] ^= tempKey[j-1][k];
    else
    {
      for(j = 1; j < uKeyColumns/2; j++)
        for (int k=0;k<4;k++)
          tempKey[j][k] ^= tempKey[j-1][k];

      tempKey[uKeyColumns/2][0] ^= S[tempKey[uKeyColumns/2 - 1][0]];
      tempKey[uKeyColumns/2][1] ^= S[tempKey[uKeyColumns/2 - 1][1]];
      tempKey[uKeyColumns/2][2] ^= S[tempKey[uKeyColumns/2 - 1][2]];
      tempKey[uKeyColumns/2][3] ^= S[tempKey[uKeyColumns/2 - 1][3]];
      for(j = uKeyColumns/2 + 1; j < uKeyColumns; j++)
        for (int k=0;k<4;k++)
          tempKey[j][k] ^= tempKey[j-1][k];
    }
    for(j = 0; (j < uKeyColumns) && (r <= aes->m_uRounds); )
    {
      for(; (j < uKeyColumns) && (t < 4); j++, t++)
        for (int k=0;k<4;k++)
          aes->m_expandedKey[r][t][k] = tempKey[j][k];
      if(t == 4)
      {
        r++;
        t = 0;
      }
    }
  }   
}

void keyEncToDec(aes_context *aes)
{
  for(int r = 1; r < aes->m_uRounds; r++)
  {
    uchar n_expandedKey[4][4];
    for (int i = 0; i < 4; i++)
      for (int j = 0; j < 4; j++)
      {
        uchar *w=aes->m_expandedKey[r][j];
        n_expandedKey[j][i]=U1[w[0]][i]^U2[w[1]][i]^U3[w[2]][i]^U4[w[3]][i];
      }
 //   memcpy(aes->m_expandedKey[r],n_expandedKey,sizeof(aes->m_expandedKey[0]));
    #pragma unroll
    for(int i = 0; i < 4; i++)
	#pragma unroll
	for(int j = 0; j < 4; j++)
	    aes->m_expandedKey[r][j][i] = n_expandedKey[j][i];
  }
} 


#define ff_poly 0x011b
#define ff_hi   0x80

#define FFinv(x)    ((x) ? pow[255 - log[x]]: 0)

#define FFmul02(x) (x ? pow[log[x] + 0x19] : 0)
#define FFmul03(x) (x ? pow[log[x] + 0x01] : 0)
#define FFmul09(x) (x ? pow[log[x] + 0xc7] : 0)
#define FFmul0b(x) (x ? pow[log[x] + 0x68] : 0)
#define FFmul0d(x) (x ? pow[log[x] + 0xee] : 0)
#define FFmul0e(x) (x ? pow[log[x] + 0xdf] : 0)
#define fwd_affine(x) \
    (w = (uint)x, w ^= (w<<1)^(w<<2)^(w<<3)^(w<<4), (uchar)(0x63^(w^(w>>8))))

#define inv_affine(x) \
    (w = (uint)x, w = (w<<1)^(w<<3)^(w<<6), (uchar)(0x05^(w^(w>>8))))

void GenerateTables()
{
  uchar pow[512],log[256];
  int i = 0, w = 1; 
  do
  {   
    pow[i] = (uchar)w;
    pow[i + 255] = (uchar)w;
    log[w] = (uchar)i++;
    w ^=  (w << 1) ^ (w & ff_hi ? ff_poly : 0);
  } while (w != 1);
 
  for (int i = 0,w = 1; i < sizeof(rcon)/sizeof(rcon[0]); i++)
  {
    rcon[i] = w;
    w = (w << 1) ^ (w & ff_hi ? ff_poly : 0);
  }
  for(int i = 0; i < 256; ++i)
  {   
    uchar b=S[i]=fwd_affine(FFinv((uchar)i));
    T1[i][1]=T1[i][2]=T2[i][2]=T2[i][3]=T3[i][0]=T3[i][3]=T4[i][0]=T4[i][1]=b;
    T1[i][0]=T2[i][1]=T3[i][2]=T4[i][3]=FFmul02(b);
    T1[i][3]=T2[i][0]=T3[i][1]=T4[i][2]=FFmul03(b);
    S5[i] = b = FFinv(inv_affine((uchar)i));
    U1[b][3]=U2[b][0]=U3[b][1]=U4[b][2]=T5[i][3]=T6[i][0]=T7[i][1]=T8[i][2]=FFmul0b(b);
    U1[b][1]=U2[b][2]=U3[b][3]=U4[b][0]=T5[i][1]=T6[i][2]=T7[i][3]=T8[i][0]=FFmul09(b);
    U1[b][2]=U2[b][3]=U3[b][0]=U4[b][1]=T5[i][2]=T6[i][3]=T7[i][0]=T8[i][1]=FFmul0d(b);
    U1[b][0]=U2[b][1]=U3[b][2]=U4[b][3]=T5[i][0]=T6[i][1]=T7[i][2]=T8[i][3]=FFmul0e(b);
  }
}
void Init(aes_context *aes, const uchar *key,uint keyLen, constant uchar * initVector){

  aes->CBCMode = true;
  GenerateTables();
  uint uKeyLenInuchars;
  switch(keyLen)
  {
    case 128:
      uKeyLenInuchars = 16;
      aes->m_uRounds = 10;
      break;
    case 192:
      uKeyLenInuchars = 24;
      aes->m_uRounds = 12;
      break;
    case 256:
      uKeyLenInuchars = 32;
      aes->m_uRounds = 14;
      break;
  }

  uchar keyMatrix[_MAX_KEY_COLUMNS][4];
//  memset(aes->m_expandedKey, 0, 15*4*4);
  #pragma unroll
  for(int i = 0; i < 15*4*4; i++)
    aes->m_initVector[i] =0 ;
  for(uint i = 0; i < uKeyLenInuchars; i++)
    keyMatrix[i >> 2][i & 3] = key[i]; 

//    memset(aes->m_initVector, 0, sizeof(aes->m_initVector));
  #pragma unroll
  for(int i = 0; i < MAX_IV_SIZE; i++)
      aes->m_initVector[i] = initVector[i];

  keySched(aes,keyMatrix);

  keyEncToDec(aes);
}

#define ROL(x,c) rotate((uint)x,(uint)c)

#define ROUNDTAIL(a,b,e,f,i,k,w)  \
	e += ROL(a,5) + f + k + w[i];  \
	b = ROL(b,30);

#define F1(b,c,d) (d ^ (b & (c ^ d)))
#define F2(b,c,d) (b ^ c ^ d)
#define F3(b,c,d) ((b & c) ^ (b & d) ^ (c & d))
#define F4(b,c,d) (b ^ c ^ d)


#define LOADSCHEDULE(i, w, block)\
        w[i] = (block+i*4)[0] << 24 | (block+i*4)[1] << 16 | (block+i*4)[2] << 8 | (block+i*4)[3];

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

void inline sha1(const uchar* msg, uint len, uchar* output){
    uint h0 = 0x67452301;
    uint h1 = 0xEFCDAB89;
    uint h2 = 0x98BADCFE;
    uint h3 = 0x10325476;
    uint h4 = 0xC3D2E1F0;
    
    uint chunks = ((len+9)/64)+1;
    uint padSpace = 64-(len%64);
    uint padInChunk;
    bool longPad;
    
    uchar msg_pad[64];
    uint w[80] = {0};
    
    if(padSpace < 9){
        padInChunk = chunks-2;
        longPad = true;
    }else{
        padInChunk = chunks-1;
        longPad = false;
    }
    
    for(uint chunk = 0;chunk<chunks;chunk++){
        
        if(chunk < padInChunk){
	    // ::memcpy(msg_pad,msg+chunk*64,64);
	    #pragma unroll
	    for (int i = 0; i < 64; i++)
		msg_pad[i]= (msg+chunk*64)[i];
        }else if(chunk == padInChunk){
            uint padStart = len%64;
            //memcpy(msg_pad,msg+chunk*64,padStart);
	    #pragma unroll
	    for (int i = 0; i < padStart; i++)
		msg_pad[i]= (msg+chunk*64)[i];
            msg_pad[padStart] = 0x80;
            if(longPad){
                // pad in last two chunks
                for(uint i = padStart+1;i<64;i++){
                    msg_pad[i] = 0;
                }
            }else{
                // pad in last chunk
                for(uint i = padStart+1;i<64-4;i++){
                    msg_pad[i] = 0;
                }
                ulong bit_len = len*8;
                msg_pad[60] = (bit_len >> 24) & 0xFF;
                msg_pad[61] = (bit_len >> 16) & 0xFF;
                msg_pad[62] = (bit_len >> 8) & 0xFF;
                msg_pad[63] = bit_len & 0xFF;
            }
        }else{
            for(uint i = 0;i<64-4;i++){
                    msg_pad[i] = 0;
            }
            ulong bit_len = len*8;
            msg_pad[60] = (bit_len >> 24) & 0xFF;
            msg_pad[61] = (bit_len >> 16) & 0xFF;
            msg_pad[62] = (bit_len >> 8) & 0xFF;
            msg_pad[63] = bit_len & 0xFF;
        }
        
        uint a = h0;
        uint b = h1;
        uint c = h2;
        uint d = h3;
        uint e = h4;

        
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

void inline sha1_loc(const local uchar* msg, uint len, uchar* output){
    
    uint h0 = 0x67452301;
    uint h1 = 0xEFCDAB89;
    uint h2 = 0x98BADCFE;
    uint h3 = 0x10325476;
    uint h4 = 0xC3D2E1F0;
    
    uint chunks = ((len+9)/64)+1;
    uint padSpace = 64-(len%64);
    uint padInChunk;
    bool longPad;
    
    uchar msg_pad[64];
    uint w[80] = {0};
    
    if(padSpace < 9){
        padInChunk = chunks-2;
        longPad = true;
    }else{
        padInChunk = chunks-1;
        longPad = false;
    }
    
    for(uint chunk = 0;chunk<chunks;chunk++){
        
        if(chunk < padInChunk){
	    // ::memcpy(msg_pad,msg+chunk*64,64);
	    #pragma unroll
	    for (int i = 0; i < 64; i++)
		msg_pad[i]= (msg+chunk*64)[i];
        }else if(chunk == padInChunk){
            uint padStart = len%64;
            //memcpy(msg_pad,msg+chunk*64,padStart);
	    #pragma unroll
	    for (int i= 0; i < padStart; i++)
		msg_pad[i]= (msg+chunk*64)[i];
            msg_pad[padStart] = 0x80;
            if(longPad){
                // pad in last two chunks
                for(uint i = padStart+1;i<64;i++){
                    msg_pad[i] = 0;
                }
            }else{
                // pad in last chunk
                for(uint i = padStart+1;i<64-4;i++){
                    msg_pad[i] = 0;
                }
                ulong bit_len = len*8;
                msg_pad[60] = (bit_len >> 24) & 0xFF;
                msg_pad[61] = (bit_len >> 16) & 0xFF;
                msg_pad[62] = (bit_len >> 8) & 0xFF;
                msg_pad[63] = bit_len & 0xFF;
            }
        }else{
            for(uint i = 0;i<64-4;i++){
                    msg_pad[i] = 0;
            }
            ulong bit_len = len*8;
            msg_pad[60] = (bit_len >> 24) & 0xFF;
            msg_pad[61] = (bit_len >> 16) & 0xFF;
            msg_pad[62] = (bit_len >> 8) & 0xFF;
            msg_pad[63] = bit_len & 0xFF;
        }
        
        uint a = h0;
        uint b = h1;
        uint c = h2;
        uint d = h3;
        uint e = h4;

        
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
void derive_key(const uchar* hash, uchar key, uchar* output){
   
    uchar key_pad[64];
    #pragma unroll
    for (int i=0; i < 64; i++)
	key_pad[i] = key;

    #pragma unroll
    for(uchar i = 0;i<20; i++)
        key_pad[i] ^= hash[i];

    sha1(key_pad,64,output);
}

void derive(const local uchar* pass, uint passLen, uchar* output){

    uchar passHash[20];
    uchar temp[40];
   
    #pragma unroll
    for (int i=0; i < 20; i++)
	passHash[i] = 0x00;
    
    sha1_loc(pass,passLen,passHash);
    derive_key((uchar*)passHash, 0x36 , (uchar*)temp);
    derive_key((uchar*)passHash, 0x5c, (uchar*)(temp+20));
    
    #pragma unroll
    for (int i=0; i < 32; i++)
	output[i] = temp[i];

}

static uint crc32_tab[] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};
uint crc32(uint crc, local uchar *buf, uchar size)
{
    const local uchar *p;
    p = buf;
    crc = crc ^ ~0U;
    while (size--)
	crc = crc32_tab[(crc ^ *p++) & 0xFF] ^ (crc >> 8);
    return crc ^ ~0U;
}

kernel void zip_staes_kernel( \
	global uchar* passwords,\
	uchar pass_len,\
	global uchar *found_flag,\
	global uint *found_vector,\
	global uchar* erdData,\
	global uchar* encData,\
	constant uchar* iv,\
	ushort passlen,\
	ushort erdSize,\
	ushort encSize,\
	local uchar* rdData,\
	local uchar* vData,\
	local uchar* tempKey){
    
    int id = get_global_id(0);
    uchar my_pass_len = passwords[id*pass_len];
    local uchar pass_buffer[32];
    uchar pb[32];
    uchar key[32];
    for(int i = 0;i<my_pass_len;i++){
        pass_buffer[i] = passwords[id*pass_len+1+i];
	pb[i] = passwords[id*pass_len+1+i];
    }

    derive(pass_buffer, my_pass_len, key);
    aes_context aes; 
    Init(&aes, key, passlen, iv);

    blockDecrypt(&aes, erdData, erdSize, rdData);
    
    #pragma unroll
    for (int i=0; i<16; i++)
	tempKey[i] = iv[i];

    #pragma unroll
    for (int i=0; i<erdSize-16; i++)
	tempKey[i+16] = rdData[i];

    derive(tempKey, erdSize, key);   
    
    Init(&aes, key, passlen, iv);

    blockDecrypt(&aes, encData, encSize, vData);
    
    uint crc = 0;

    crc = crc ^ vData[encSize-1];
    crc = crc << 8 ^ vData[encSize-2];
    crc = crc << 8 ^ vData[encSize-3];
    crc = crc << 8 ^ vData[encSize-4];
    
    uint crc3 = crc32(0, vData, encSize-4); 
    if (crc != crc3){
        return;
    }
    
    *found_flag = 1;
    uint big_pos = id/32;
    uint small_pos = id%32;
    uint val = 0x80000000 >> small_pos;
    atomic_or(found_vector+big_pos,val);
}
