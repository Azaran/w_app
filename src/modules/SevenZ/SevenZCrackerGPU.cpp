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
 
 #include "SevenZCrackerGPU.h"
 
 SevenZCrackerGPU::SevenZCrackerGPU(SevenZInitData *data){
     cpu = new SevenZCrackerCPU(data);
     kernelFile = "kernels/sevenz_aes_kernel.cl";
     kernelName = "sevenz_aes_kernel";
 }
 
 SevenZCrackerGPU::SevenZCrackerGPU(const SevenZCrackerGPU& orig){
 }
 
 SevenZCrackerGPU::~SevenZCrackerGPU() {
 }
 
 bool SevenZCrackerGPU::initData() {
    uint32_t gws = deviceConfig.globalWorkSize;
    uint8_t initial_val = 0;
    aes_buffer = cl::Buffer(context, CL_MEM_WRITE_ONLY, gws*sizeof(uint32_t)*AES_NUM_IVMRK_WORDS+3);
     first_block = cl::Buffer(context,CL_MEM_WRITE_ONLY,sizeof(char)*DECODE_BLOCK_SIZE);
     iv = cl::Buffer(context,CL_MEM_WRITE_ONLY,sizeof(char)*DECODE_BLOCK_SIZE);
     
     que.enqueueWriteBuffer(aes_buffer, CL_TRUE, 0, sizeof(uint32_t)*gws, &initial_val);
     que.enqueueWriteBuffer(first_block, CL_TRUE, 0, sizeof(char)*DECODE_BLOCK_SIZE, cpu->check_data.encData);
     que.enqueueWriteBuffer(iv, CL_TRUE, 0, sizeof(char)*DECODE_BLOCK_SIZE, cpu->iv);
     
     kernel.setArg(userParamIndex, first_block);
     kernel.setArg(userParamIndex+1, iv);
     kernel.setArg(userParamIndex+2, aes_buffer);
     return true;
 }
 
 bool SevenZCrackerGPU::verifyPassword(std::string& pass) {
     return !cpu->checkPassword(&pass);
 }
 
 
 
