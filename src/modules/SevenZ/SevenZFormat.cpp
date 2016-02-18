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
#include "SevenZCrackerCPU.h"
#include "SevenZCrackerGPU.h"
#include "Utils.h"
#include "CrackerFactoryTemplate.tcc"
#include <fstream>
#include <cstring>
#include <iostream>

#define SHL(x) (x = x << 1) // shift left by one bit 


typedef CrackerFactoryTemplate<SevenZCrackerCPU,std::vector<SevenZInitData>*> SevenZCrackerCPUFactory;

typedef CrackerFactoryTemplate<SevenZCrackerGPU,std::vector<SevenZInitData>*, true> SevenZCrackerGPUFactory;

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

/*
SevenZInitData SevenZFormat::readOneFile(std::ifstream *stream){
	
    /// TODO: Browse SevenZ structure and find data
    

    return NULL;
    //return data;
}
*/
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
    uint8_t num[bytes];
    num[0] = firstByte >> (bytes - 1);    // MSB
//    std::cout << "num[0]: " << std::bitset<8>(num[0]) << std::endl;
    if (bytes > 1)
	stream->read(reinterpret_cast<char*>(&num[1]), bytes-1);

    uint64_t sum = 0;
    while(bytes-- > 0)
	sum += Utils::pow(256,bytes) * num[bytes];
    
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
    SevenZCoder *coder = folder.coder = new SevenZCoder[folder.numCoders];
    for (int i = 0; i < folder.numCoders; i++){
	stream->read(reinterpret_cast<char*>(&coder->flags), 1);
	coder->coderIDSize = (coder->flags & 0x0f);
	coder->coderID = new uint8_t[coder->coderIDSize];
	if (coder->flags & 0x10){
	    folder.numInStreamsTotal += coder->numInStreams = SevenZUINT64(stream);
	    folder.numOutStreamsTotal += coder->numInStreams = SevenZUINT64(stream);
	}
	if (coder->flags & 0x20){
	    coder->propertySize = SevenZUINT64(stream);
	    coder->property = new uint8_t[coder->propertySize];
	    stream->read(reinterpret_cast<char*>(&coder->property), coder->propertySize);
	}
    }

    for (int i = 0; i < (folder.numOutStreamsTotal-1); i++){
	folder.inIndex = SevenZUINT64(stream);
	folder.outIndex = SevenZUINT64(stream);
    }
    uint8_t numPackStreams = folder.numInStreamsTotal - folder.numOutStreamsTotal - 1;
    if (numPackStreams > 1){
	folder.index = new uint64_t[numPackStreams];
	for (int i = 0; i < numPackStreams; i++)	
	    folder.index[i] = SevenZUINT64(stream);
    }
    return folder;
}



void SevenZFormat::readMainHeader(std::ifstream *stream){
    uint8_t subHdrID;
    uint64_t numInStreams = 0;
    uint64_t numOutStreams = 0;

    stream->read(reinterpret_cast<char*>(&subHdrID), 1);
    while (subHdrID != 0){   // End 
	std::cout << "subHdrID: " << std::bitset<8>(subHdrID) << std::endl;
	if (subHdrID == 0x06){   // PackInfo
	    uint64_t packPos = SevenZUINT64(stream);
	    uint64_t numPackStreams = SevenZUINT64(stream);
	    uint8_t subsubHdrID = 1; // we just have get into the cycle
	    while (subsubHdrID != 0){   // End 
		stream->read(reinterpret_cast<char*>(&subsubHdrID), 1);
		std::cout << "subsubHdrID: " << std::bitset<8>(subsubHdrID) << std::endl;
		if (subsubHdrID == 0x09){ // Size
		    uint64_t packSize[numPackStreams];
		    for (int i = 0; i < numPackStreams; i++)
			packSize[i] = SevenZUINT64(stream);
		}else if (subsubHdrID == 0x0A){	    // CRC
		    for (int i = 0; i < numPackStreams; i++){
			uint8_t aad;
			stream->read(reinterpret_cast<char*>(&aad), 1);
			if (aad == 0){
			    std::cerr << "File reading error. AllAreDefined == 0." << std::endl;	// TODO: figure out how AAD works
			    exit(153);
			}
			for (int j = 0; j < aad; j++)
			    stream->seekg(4, stream->cur);  // CRCs[NumDefined]

			// TODO: infinite cycle "YOU BETTER FIX IT"
		    }
		}
	    }
	}else if (subHdrID == 0x07){ //Coders Info
	    uint8_t subsubHdrID = 1; // we just have get into the cycle
	    stream->read(reinterpret_cast<char*>(&subsubHdrID), 1);	// Folder (0x0B)
	    std::cout << "subsubHdrID2: " << std::bitset<8>(subsubHdrID) << std::endl;
	    
	    uint64_t numFolders = SevenZUINT64(stream);
	    SevenZFolder folder[numFolders];
	    uint8_t external;
	    stream->read(reinterpret_cast<char*>(&external), 1);
	    if (external == 1){
		std::cerr << "Unsupporte value. External == 1." << std::endl;	// TODO: add support for work with datastream indexes
		exit(154);
	    }else{
		for (int i = 0; i < numFolders; i++)
		    folder[i] = readFolder(stream);
	    }
	    
	    stream->read(reinterpret_cast<char*>(&subsubHdrID), 1);	// CodersUnPackSize (0x0C)
	    std::cout << "subsubHdrID: " << std::bitset<8>(subsubHdrID) << std::endl;
	    for (int i = 0; i < numFolders; i++){
		folder[i].unPackSize = new uint64_t[folder[i].numOutStreamsTotal];
		for (int j = 0; j < folder[i].numOutStreamsTotal; j++)
		    folder[i].unPackSize[j] = SevenZUINT64(stream);
	    }

	}
    }
}

void SevenZFormat::readInitInfo(std::ifstream *stream){

    uint8_t hdrID;
    SevenZStartHdr sighdr = readStartHdr(stream);
    stream->seekg(sighdr.NxtHdrOffset,stream->cur); // move to Main Header
    stream->read(reinterpret_cast<char*>(&hdrID), 1);
    std::cout << "hdrID: " << std::bitset<8>(hdrID) << std::endl;
    if (hdrID == 0x1){
	// raw Main Header
        readMainHeader(stream); 
    }else if (hdrID == 0x17){
	// header of compressed or encrypted Main Header
	readMainHeader(stream); 
    }


}
void SevenZFormat::init(std::string& filename){
    std::ifstream stream;
    stream.open(filename,std::ios_base::binary);
    char buffer[6];
    
    readInitInfo(&stream);
    

    
/*
    do{
        SevenZInitData filedata = readOneFile(&stream);
        stream.read(reinterpret_cast<char*>(buffer),4);
        data.push_back(filedata);
        filterData();
        if(::memcmp(buffer,"7z\xBC\xAF\x27\x1C",6) == 0){
            stream.seekg(-6,stream.cur);
        }else {
           break;
        }
    }while(true);
*/
    if (verbose){
        // Print SevenZ encryption information obtained from the file
        std::cout << "======= SevenZ information =======" << std::endl;
/*
	if (data[0].type == SevenZ){
            std::cout << "Encryption method: SevenZAES256" << std::endl;
//            std::cout << "Key length: " << (int)(data[0].keyLength) << "b" << std::endl;
//            std::cout << "Salt length: " << (int)(data[0].saltLen)*8 << "b" << std::endl;
	}else 
            std::cout << "Encryption method is currently not supported by Wrathion." << std::endl;
*/        
        std::cout << "===============================" << std::endl;
    }
    stream.close();
    is_supported = true;
}

void SevenZFormat::filterData(){
    if(data.size() < 2)
        return;
    
    uint32_t minSize = UINT32_MAX;
    uint32_t minIndex = 0;
    for(int i = 0;i<data.size();i++){
        if(data[i].dataLen > 0 && minSize > data[i].dataLen){
            minSize = data[i].dataLen;
            minIndex = i;
        }
    }
    
    for(int i = 0;i<data.size();i++){
        if(i == minIndex)
            continue;
        
        data[i].dataLen = 0;
        delete[] data[i].encData;
        data[i].encData = NULL;
    }
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

SevenZInitData::SevenZInitData(const SevenZInitData& orig){
    /*this->type = orig.type;
    this->crc32 = orig.crc32;
    this->dataLen = orig.dataLen;
    this->uncompressedSize = orig.uncompressedSize;
    this->keyLength = orig.keyLength;
    this->compression = orig.compression;
    this->encSize = orig.encSize;
    this->erdSize = orig.erdSize;
    this->ivSize = orig.ivSize;
    this->encData = orig.encData;
    this->erdData = orig.erdData;
    this->ivData = orig.ivData;
    this->saltLen = orig.saltLen;
    ::memcpy(this->salt,orig.salt,16);
    ::memcpy(this->verifier,orig.verifier,2);
    ::memcpy(this->authCode,orig.authCode,10);
    ::memcpy(this->streamBuffer,orig.streamBuffer,12);*/
}

