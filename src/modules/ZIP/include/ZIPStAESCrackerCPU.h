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

#ifndef ZIPStAESCRACKERCPU_H
#define	ZIPStAESCRACKERCPU_H

#include "Cracker.h"
#include "ZIPFormat.h"
#include <pthread.h>
#include "rijndael.h"


/**
 * Class for Standard ZIP AES Cracking
 */
class ZIPStAESCrackerCPU: public Cracker {
public:
    ZIPStAESCrackerCPU(std::vector<ZIPInitData> *data);
    ZIPStAESCrackerCPU(const ZIPStAESCrackerCPU& orig);
    virtual ~ZIPStAESCrackerCPU();
    //virtual void run();

    virtual CheckResult checkPassword(const std::string* password);

    /**
     * Calculate SHA1 hash of message
     * @param msg, len, output
     */
    void sha1(const uint8_t* msg,unsigned int len,uint8_t* output);
    /**
     * Similar to Microsoft CryptoDeriveKey()
     * @param msg, msgLen, output
     */
    void derive_key(const uint8_t* hash, uint8_t key, uint8_t* output);
    /**
     * Similar to Microsoft CryptoDeriveKey()
     * @param pass, passLen, output
     */
    void derive(const uint8_t* pass, unsigned int passLen, uint8_t* output);
    
    uint8_t key[32];
    uint8_t *rdData;
    uint8_t *vData;
    uint8_t *tempKey;
    std::vector<ZIPInitData> *data;
    ZIPInitData check_data;
    Rijndael aes;
};

#endif	/* ZIPStAESCRACKERCPU_H */

