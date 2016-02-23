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

#include "SevenZFormat.h"
//#include "SevenZCrackerCPU.h"
//#include "SevenZCrackerGPU.h"
#include "CrackerFactoryTemplate.tcc"
#include <fstream>
#include <cstring>
#include <iostream>

#define SHL(x) (x = x << 1) // shift left by one bit 


//typedef CrackerFactoryTemplate<SevenZCrackerCPU,std::vector<SevenZInitData>*> SevenZCrackerCPUFactory;

//typedef CrackerFactoryTemplate<SevenZCrackerGPU,std::vector<SevenZInitData>*, true> SevenZCrackerGPUFactory;

SevenZFormat::SevenZFormat(){
    signature = "7z\xBC\xAF\x27\x1C";
    ext = "7z";
    name = "SevenZ";
    
    /*
     * We are unable to detect if SevenZ format is encrypted,
     * so we suppose, it is.
     */
    is_encrypted = true;
}

SevenZFormat::SevenZFormat(const SevenZFormat& orig):FileFormat(orig){
}

SevenZFormat::~SevenZFormat(){   
}

uint64_t SevenZFormat::SevenZUINT64(std::ifstream *stream){
    int bytes = 1;
    uint8_t firstByte;
    
    stream->read(reinterpret_cast<char*>(&firstByte), 1);
//    std::cout << "firstByte: " << std::bitset<8>(firstByte) << std::endl;
    while (firstByte & 0x80){
	SHL(firstByte);
	bytes++;
    }

//    std::cout << "bytes: " << bytes << std::endl;
//    std::cout << "firstByte: " << std::bitset<8>(firstByte) << std::endl;
    uint8_t num[bytes];
    num[bytes - 1] = firstByte >> (bytes - 1);    // MSB
    if (bytes > 1)
	stream->read(reinterpret_cast<char*>(&num[0]), bytes-1);

    uint64_t sum = 0;
    for (int i = bytes - 1; i >= 0; i--)	
	sum = ((sum | num[i]) << (i * 8));

    return sum;
}

SevenZStartHdr SevenZFormat::readStartHdr(std::ifstream *stream){

    SevenZStartHdr header;
    stream->seekg(12,stream->cur);   // 6 signature, 2 version, 4 sigCRC
    stream->read(reinterpret_cast<char*>(&header.NxtHdrOffset),sizeof(uint64_t));
    stream->read(reinterpret_cast<char*>(&header.NxtHdrSize),sizeof(uint64_t));
    stream->seekg(4,stream->cur);   // NextHeaderCRC

    return header;
}

SevenZFolder SevenZFormat::readFolder(std::ifstream *stream){
    SevenZFolder folder;
    folder.numCoders = SevenZUINT64(stream);
//  std::cout << "numCoders: " << folder.numCoders << std::endl;
    folder.coder = new SevenZCoder[folder.numCoders];
    for (uint8_t i = 0; i < folder.numCoders; i++){
	SevenZCoder *coder = &(folder.coder[i]); 
	stream->read(reinterpret_cast<char*>(&coder->flags), 1);
	coder->coderIDSize = (coder->flags & 0x0f);
//	std::cout << "codec->coderIDSize: " << coder->coderIDSize << std::endl;
	coder->coderID = new uint8_t[coder->coderIDSize];
	stream->read(reinterpret_cast<char*>(&coder->coderID), coder->coderIDSize);
	// most important and common IDs:
	// 03 01 01 - 7z LZMA
	// 06 f1 07 01 - 7zAES (AES-256 + SHA-256)
	
	if (coder->flags & 0x10){
	    coder->numInStreams = SevenZUINT64(stream);
	    folder.numInStreamsTotal += coder->numInStreams;
//	    std::cout << "numInStreams: " << coder->numInStreams << std::endl;
//	    std::cout << "numInStreamsTotal: " << folder.numInStreamsTotal << std::endl;

	    coder->numOutStreams = SevenZUINT64(stream);
	    folder.numOutStreamsTotal += coder->numOutStreams;
//	    std::cout << "numOutStreams: " << coder->numOutStreams << std::endl;
//	    std::cout << "numOutStreamsTotal: " << folder.numOutStreamsTotal << std::endl;
	}else {
	    // TODO: check this in the 7z sources
	    folder.numInStreamsTotal++;
	    folder.numOutStreamsTotal++;
	}
	if (coder->flags & 0x20){
	    coder->propertySize = SevenZUINT64(stream);
//	    std::cout << "propertySize: " << coder->propertySize << std::endl;
	    coder->property = new uint8_t[coder->propertySize];
	    stream->read(reinterpret_cast<char*>(&coder->property), coder->propertySize);
	}
//	std::cout << "coder->flags: " << std::bitset<8>(coder->flags) << std::endl;
//    std::cout << "numInStreamsTotal: " << folder.numOutStreamsTotal << std::endl;
//    std::cout << "numOutStreamsTotal: " << folder.numOutStreamsTotal << std::endl;
    }


    for (uint64_t i = 0; i < (folder.numOutStreamsTotal - 1); i++){
	folder.inIndex = SevenZUINT64(stream);
	folder.outIndex = SevenZUINT64(stream);
    }

    uint64_t numPackStreams = folder.numInStreamsTotal - (folder.numOutStreamsTotal - 1);
//    std::cout << "numPackStreams: " << numPackStreams << std::endl;
    if (numPackStreams > 1){
	numPackStreams--;
	folder.index = new uint64_t[numPackStreams];
	for (uint8_t i = 0; i < numPackStreams; i++)	
	    folder.index[i] = SevenZUINT64(stream);
    }
    return folder;
}

uint32_t* SevenZFormat::CRCHdr(std::ifstream *stream, uint64_t numPackStreams,bool skip){  // 0x0A
    uint32_t* CRC;
    if (!skip)
	CRC = new uint32_t[numPackStreams];
    for (uint64_t i = 0; i < numPackStreams; i++){
	uint8_t aad;
	stream->read(reinterpret_cast<char*>(&aad), 1);
	if (aad == 0){
	    std::cerr << "File reading error. AllAreDefined == 0." << std::endl;	// TODO: figure out how AAD works
	    exit(153);
	}
	for (uint8_t j = 0; j < aad; j++)
	    if(skip)
		stream->seekg(4, stream->cur);
	    else
		stream->read(reinterpret_cast<char*>(&(CRC[j])), 4);  // CRCs[NumDefined]
    }
    return (skip ? NULL : CRC);
}

void SevenZFormat::PackInfoHdr(std::ifstream *stream){	// 0x06
    SevenZPackInfoHdr *packInfo = new SevenZPackInfoHdr;
    packInfo->packPos = 32 + SevenZUINT64(stream); // offset starting at 0x20 after startHeader
    packInfo->numPackStreams = SevenZUINT64(stream);

    uint8_t subsubHdrID = 1; // we just have to get into the cycle
    while (subsubHdrID != 0){   // End 
	stream->read(reinterpret_cast<char*>(&subsubHdrID), 1);
//	std::cout << "subsubHdrID: " << std::bitset<8>(subsubHdrID) << std::endl;
	if (subsubHdrID == 0x09){   // Size
	    packInfo->packSize = new uint64_t[packInfo->numPackStreams];
	    for (uint64_t i = 0; i < packInfo->numPackStreams; i++)
		packInfo->packSize[i] = SevenZUINT64(stream);
	}else if (subsubHdrID == 0x0a){
	    packInfo->CRC = new uint32_t[packInfo->numPackStreams];
	    for (uint64_t i = 0; i < packInfo->numPackStreams; i++)
		packInfo->CRC = CRCHdr(stream, packInfo->numPackStreams, READ);
	}
    }
    this->data.packInfo = packInfo;
}

void SevenZFormat::CodersHdr(std::ifstream *stream){	// 0x07
    uint8_t subsubHdrID;
    stream->read(reinterpret_cast<char*>(&subsubHdrID), 1);	// Folder (0x0B)
//    std::cout << "subsubHdrID: " << std::bitset<8>(subsubHdrID) << std::endl;

    this->data.numFolders = SevenZUINT64(stream);
//    std::cout << "this->data.numFolders: " << this->data.numFolders << std::endl;
    this->data.folders = new SevenZFolder[this->data.numFolders];
    uint8_t ext;
    stream->read(reinterpret_cast<char*>(&ext), 1);
    if (ext == 1){
	std::cerr << "Unsupporte value. External == 1." << std::endl;	// TODO: add support for work with datastream indexes
	exit(154);
    }else{
	for (uint64_t i = 0; i < this->data.numFolders; i++)
	    this->data.folders[i] = readFolder(stream);
    }

    stream->read(reinterpret_cast<char*>(&subsubHdrID), 1);	// CodersUnPackSize (0x0C)
//    std::cout << "subsubHdrID2: " << std::bitset<8>(subsubHdrID) << std::endl;
    if (subsubHdrID == 0x0c){
	for (uint64_t i = 0; i < this->data.numFolders; i++){
	    this->data.folders[i].unPackSize = new uint64_t[this->data.folders[i].numOutStreamsTotal];
//	    std::cout << "this->data.numFolders: " << std::bitset<8>(this->data.numFolders) << std::endl;
//	    std::cout << "numOutStreamsTotal: " << std::bitset<8>(this->data.folders[i].numOutStreamsTotal) << std::endl;
	    for (uint64_t j = 0; j < this->data.folders[i].numOutStreamsTotal; j++)
	    {
		this->data.folders[i].unPackSize[j] = SevenZUINT64(stream);
//		std::cout << "unPackSize: " << std::bitset<24>(this->data.folders[i].unPackSize[j]) << std::endl;
	    }
	}
	stream->read(reinterpret_cast<char*>(&subsubHdrID), 1);	// CRCs (0x0A)
//	std::cout << "subsubHdrID3: " << std::bitset<8>(subsubHdrID) << std::endl;
    }

    if (subsubHdrID == 0x0a)	    // CRC
	CRCHdr(stream, this->data.numFolders, SKIP);

    stream->read(reinterpret_cast<char*>(&subsubHdrID), 1);	// kEnd (0x00)

}

void SevenZFormat::readHeader(std::ifstream *stream){
    uint8_t subHdrID = 1;   // we just wanna get into the cycle
    while (subHdrID != 0){   // End 
	stream->read(reinterpret_cast<char*>(&subHdrID), 1);
//	std::cout << "subHdrID: " << std::bitset<8>(subHdrID) << std::endl;
	if (subHdrID == 0x06)   // PackInfo
	    PackInfoHdr(stream);
	else if (subHdrID == 0x07){ //Coders Info
	    CodersHdr(stream);
	    subHdrID = 0;	// fixed end we have all info we need
//	    stream->read(reinterpret_cast<char*>(&subHdrID), 1);	// kEnd (0x00) {fileend}
	}
    }
}

void SevenZFormat::readInitInfo(std::ifstream *stream){

    uint8_t hdrID;
    SevenZStartHdr sighdr = readStartHdr(stream);
    stream->seekg(sighdr.NxtHdrOffset,stream->cur); // move to Main Header
    stream->read(reinterpret_cast<char*>(&hdrID), 1);
//  std::cout << "hdrID: " << std::bitset<8>(hdrID) << std::endl;
    if (hdrID == 0x1){
	// raw Main Header 
	// only when only one file is compress and Header is not encrypted
        readHeader(stream); 
    }else if (hdrID == 0x17){
	readHeader(stream); 
	// TODO: Decompress and decrypt Main header 
    }


}
void SevenZFormat::init(std::string& filename){
    std::ifstream stream;
    stream.open(filename,std::ios_base::binary);
    char buffer[6];
    
    readInitInfo(&stream);
    
    if (verbose){
        // Print SevenZ encryption information obtained from the file
        std::cout << "======= SevenZ information =======" << std::endl;
/*
	if (data[0].type == SevenZ){
            std::cout << "Encryption method: SevenZAES256" << std::endl;
            std::cout << "Key length: " << (int)(data[0].keyLength) << "b" << std::endl;
            std::cout << "Salt length: " << (int)(data[0].saltLen)*8 << "b" << std::endl;
	}else 
            std::cout << "Encryption method is currently not supported by Wrathion." << std::endl;
*/        
        std::cout << "===============================" << std::endl;
    }
    stream.close();
    is_supported = true;
}


CrackerFactory* SevenZFormat::getCPUCracker(){
//    if(data[0].type == SevenZAES)
//	return new SevenZCrackerGPUFactory(&data);
//    else 
	return NULL;
}

CrackerFactory* SevenZFormat::getGPUCracker(){
//    if(data[0].type == SevenZAES)
//	return new SevenZCrackerGPUFactory(&data);
//    else 
	return NULL;
}

SevenZInitData::SevenZInitData(){
    
}
/*
SevenZInitData::SevenZInitData(const SevenZInitData& orig){
    this->data.type = orig.type;
    this->data.crc32 = orig.crc32;
    this->data.dataLen = orig.dataLen;
    this->data.uncompressedSize = orig.uncompressedSize;
    this->data.keyLength = orig.keyLength;
    this->data.compression = orig.compression;
    this->data.encSize = orig.encSize;
    this->data.erdSize = orig.erdSize;
    this->data.ivSize = orig.ivSize;
    this->data.encData = orig.encData;
    this->data.erdData = orig.erdData;
    this->data.ivData = orig.ivData;
    this->data.saltLen = orig.saltLen;
    ::memcpy(this->data.salt,orig.salt,16);
    ::memcpy(this->data.verifier,orig.verifier,2);
    ::memcpy(this->data.authCode,orig.authCode,10);
    ::memcpy(this->data.streamBuffer,orig.streamBuffer,12);
}
*/

