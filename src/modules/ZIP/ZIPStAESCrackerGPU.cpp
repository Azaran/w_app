/* 
 * Copyright (C) 2016 Vojtech Vecera
 * * 
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

#include "ZIPStAESCrackerGPU.h"

ZIPStAESCrackerGPU::ZIPStAESCrackerGPU(std::vector<ZIPInitData> *data) {
    cpu = new ZIPStAESCrackerCPU(data); 
    kernelFile = "kernels/zip_staes_kernel.cl";
    kernelName = "zip_staes_kernel";

}

ZIPStAESCrackerGPU::ZIPStAESCrackerGPU(const ZIPStAESCrackerGPU& orig) {
}

ZIPStAESCrackerGPU::~ZIPStAESCrackerGPU() {
}

bool ZIPStAESCrackerGPU::initData() {
    erdData = cl::Buffer(context, CL_MEM_READ_WRITE, cpu->check_data.erdSize);
    encData = cl::Buffer(context, CL_MEM_READ_WRITE, cpu->check_data.encSize);
    iv =      cl::Buffer(context, CL_MEM_READ_WRITE, 16); 
    uint16_t gws = deviceConfig.globalWorkSize;
    uint8_t initBufferValue = 0;

    g_buffer = cl::Buffer(context, CL_MEM_READ_WRITE, gws*(2*cpu->check_data.erdSize+cpu->check_data.encSize));
    // Passing data to the kernel via global memory
    que.enqueueWriteBuffer(erdData, CL_TRUE, 0,\
	    cpu->check_data.erdSize,
	    cpu->check_data.erdData);
    que.enqueueWriteBuffer(encData,
	    CL_TRUE, 0,\
	    cpu->check_data.encSize,
	    cpu->check_data.encData);
    que.enqueueWriteBuffer(iv,
	    CL_TRUE, 0, 16,
	    cpu->check_data.ivData);
    que.enqueueFillBuffer(g_buffer,
	    &initBufferValue,
	    sizeof(uint8_t),
	    gws*(2*cpu->check_data.erdSize+cpu->check_data.encSize),
	    NULL, NULL);

    kernel.setArg(userParamIndex,
	    erdData);
    kernel.setArg(userParamIndex+1,
	    encData);
    kernel.setArg(userParamIndex+2,
	    g_buffer);
    kernel.setArg(userParamIndex+3,
	    iv);
    kernel.setArg(userParamIndex+4,
	    cpu->check_data.keyLength);
    kernel.setArg(userParamIndex+5,
	    cpu->check_data.erdSize);
    kernel.setArg(userParamIndex+6,
	    cpu->check_data.encSize);

    return
	true;
}


bool ZIPStAESCrackerGPU::verifyPassword(std::string& pass) {
     return !cpu->checkPassword(&pass);
}
