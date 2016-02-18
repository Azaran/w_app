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

#ifndef SevenZFORMAT_H
#define	SevenZFORMAT_H

#include "FileFormat.h"
#include <vector>
#include <cassert>
#include <bitset>

/**
 * Type of file encryption
 */
enum SevenZEncType{
    SevenZAES,
    NONE
};

struct SevenZCoder{
    uint8_t flags;
    uint8_t coderIDSize;
    uint8_t *coderID;
    uint64_t numInStreams;
    uint64_t numOutStreams;
    uint64_t propertySize;
    uint8_t *property;
};

struct SevenZFolder{
    uint64_t numCoders;
    SevenZCoder *coder;
    uint64_t numInStreamsTotal = 0;
    uint64_t numOutStreamsTotal = 1;
    uint64_t inIndex;
    uint64_t outIndex;
    uint64_t *unPackSize;
    uint64_t *index;
};

struct SevenZStartHdr{
    uint64_t NxtHdrOffset;
    uint64_t NxtHdrSize;
};

struct SevenZInitData{
    SevenZInitData();
    SevenZInitData(const SevenZInitData &orig);
    SevenZEncType type;
    uint32_t crc32;
    uint32_t dataLen;
    uint32_t uncompressedSize;
    uint16_t keyLength;
    uint16_t compression;
    uint16_t encSize;
    uint16_t erdSize;
    uint16_t ivSize;
    uint8_t *encData;
    uint8_t *erdData;
    uint8_t *ivData;
    uint8_t saltLen;
    uint8_t salt[16];
    uint8_t verifier[2];
    uint8_t authCode[10];
    uint8_t streamBuffer[12];
};

/**
 * Class for reading SevenZ file
 */
class SevenZFormat: public FileFormat {
public:
    SevenZFormat();
    SevenZFormat(const SevenZFormat& orig);
    virtual ~SevenZFormat();
    virtual void init(std::string& filename);
    virtual CrackerFactory* getCPUCracker();
    virtual CrackerFactory* getGPUCracker();


protected:
    /**
     * Read one file in stream from PK\x03\x04 signature position
     * @param stream
     * @return 
     */
    SevenZInitData readOneFile(std::ifstream *stream);
    SevenZStartHdr readStartHdr(std::ifstream *stream);
    SevenZFolder readFolder(std::ifstream *stream);
    uint64_t SevenZUINT64(std::ifstream *stream);
    void CRCHdr(std::ifstream *stream, uint64_t numPackStreams);
    void readInitInfo(std::ifstream *stream);
    void readMainHeader(std::ifstream *stream);
    /**
     * Removes all files, except the smallest one
     */
    void filterData();
    
private:
    std::vector<SevenZInitData> data;

};

#endif	/* SevenZFORMAT_H */

