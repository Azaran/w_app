/* 
 * Copyright (C) 2016 Vojtech Vecera
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

#ifndef ZIPTDESCRACKERCPU_H
#define	ZIPTDESCRACKERCPU_H

#include "Cracker.h"
#include "ZIPFormat.h"
#include <pthread.h>


/**
 * Class for Standard ZIP AES Cracking
 */
class ZIPTDESCrackerCPU: public Cracker {
public:
    ZIPTDESCrackerCPU(std::vector<ZIPInitData> *data);
    ZIPTDESCrackerCPU(const ZIPTDESCrackerCPU& orig);
    virtual ~ZIPTDESCrackerCPU();
    //virtual void run();

    virtual CheckResult checkPassword(const std::string* password);

protected:
    /**
     * Calculate SHA1 hash of message
     * @param msg input to hash
     * @param len input legth
     * @param output result hash
     */
    void sha1(const uint8_t* msg,unsigned int len,uint8_t* output);
    /**
     * Similar to Microsoft CryptoDeriveKey()
     * @param msg input to SHA1
     * @param msgLen input length
     * @param output result SHA1 hash
     */
    void derive_key(const uint8_t* hash, uint8_t key, uint8_t* output);
    /**
     * Similar to Microsoft CryptoDeriveKey()
     * @param pass password
     * @param passLen passwoed length
     * @param output result key (hash)
     */
    void derive(const uint8_t* pass, unsigned int passLen, uint8_t* output);
    void prepareKey(uint8_t *key, uint8_t *output);
    
    void tdesDecrypt(uint8_t *key, uint8_t *data, uint32_t dataLen, uint8_t *output);
    uint8_t key[32];
    uint8_t *rdData;
    uint8_t *vData;
    uint8_t *tempKey;
    std::vector<ZIPInitData> *data;
    ZIPInitData check_data;
};

#endif	/* ZIPTDESCRACKERCPU_H */

