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

#ifndef ZIPStAESCRACKERCPU_H
#define	ZIPStAESCRACKERCPU_H

#include "Cracker.h"
#include "ZIPFormat.h"
#include <pthread.h>


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

protected:
    /**
     * Calculate SHA1 hash of message
     * @param msg input to hash
     * @param len input legth
     * @param output result hash
     */
    void sha1(const uint8_t* msg,unsigned int len,uint8_t* output);
    /**
     * @param msg input to HMAC
     * @param msgLen input length
     * @param key key to auth
     * @param keyLen key length
     * @param output result HMAC
     */
    void derive_key(const uint8_t* hash, uint8_t key, uint8_t* output);
    /**
     * @param pass password
     * @param passLen passwoed length
     * @param output result key
     */
    void derive(const uint8_t* pass, unsigned int passLen, uint8_t* output);
    
    std::vector<ZIPInitData> *data;
    ZIPInitData check_data;
};

#endif	/* ZIPStAESCRACKERCPU_H */

