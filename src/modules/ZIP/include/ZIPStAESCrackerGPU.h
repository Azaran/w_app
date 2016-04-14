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

#ifndef ZIPStAESCRACKERGPU_H
#define	ZIPStAESCRACKERGPU_H

#include "ZIPStAESCrackerCPU.h"
#include "GPUCracker.h"
#include "ZIPFormat.h"
#include <vector>
#include <iostream>


class ZIPStAESCrackerGPU: public GPUCracker {
public:
    ZIPStAESCrackerGPU(std::vector<ZIPInitData> *data);
    ZIPStAESCrackerGPU(const ZIPStAESCrackerGPU& orig);
    virtual ~ZIPStAESCrackerGPU();

    virtual bool initData();
    virtual bool verifyPassword(std::string& pass);
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
    
    ZIPStAESCrackerCPU *cpu; 
    ZIPInitData data;

    cl::Buffer erdData;
    cl::Buffer encData;
    cl::Buffer iv;
};

#endif	/* ZIPStAESCRACKERGPU_H */

