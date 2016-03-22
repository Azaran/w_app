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

#ifndef SevenZCRACKERCPU_H
#define	SevenZCRACKERCPU_H

#include "Cracker.h"
#include "SevenZFormat.h"
#include <pthread.h>


/**
 * Class for Standard ZIP AES Cracking
 */
class SevenZCrackerCPU: public Cracker {
public:
    SevenZCrackerCPU(SevenZInitData *data);
    SevenZCrackerCPU(const SevenZCrackerCPU& orig);
    virtual ~SevenZCrackerCPU();
    //virtual void run();

    virtual CheckResult checkPassword(const std::string* password);

protected:
    /**
     * Similar to Microsoft CryptoDeriveKey()
     * @param msg input to SHA1
     * @param msgLen input length
     * @param output result SHA1 hash
     */
    void prepareKey(const std::string* pass, std::string* output);
    /**
     * Similar to Microsoft CryptoDeriveKey()
     * @param pass password
     * @param passLen passwoed length
     * @param output result key (hash)
     */
    void derive(const std::string* pass, uint8_t* output);
    
    uint8_t key[32];
    uint8_t iv[16] = {0};
    uint64_t destlen;
    uint64_t srclen;
    uint8_t *data;
    uint8_t *raw;
   // SevenZInitData *data;
    SevenZInitData check_data;
};

#endif	/* SevenZCRACKERCPU_H */

