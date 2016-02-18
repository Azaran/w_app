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

#ifndef SevenZCRACKERGPU_H
#define	SevenZCRACKERGPU_H

#include "SevenZFormat.h"
#include "GPUCracker.h"
#include "SevenZCracker.h"

/**
 * Class for PKSevenZ Stream Cipher cracking on GPU
 */
class SevenZCrackerGPU: public GPUCracker, protected SevenZCracker {
public:
    SevenZCrackerGPU(std::vector<SevenZInitData> *data);
    SevenZCrackerGPU(const SevenZCrackerGPU& orig);
    virtual ~SevenZCrackerGPU();
    
    virtual void sharedDataInit();

    virtual bool verifyPassword(std::string& pass);
    virtual bool initData();
    

    virtual void debugKernel(int clFinishRes);


private:
    cl::Buffer crcTable_buffer;
    cl::Buffer lastCRCByte_buffer;
    cl::Buffer randomStream_buffer;
    cl::Buffer debug_buffer;

};

#endif	/* SevenZCRACKERGPU_H */

