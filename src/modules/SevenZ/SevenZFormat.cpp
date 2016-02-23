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



//typedef CrackerFactoryTemplate<SevenZCrackerCPU,vector<SevenZInitData>*> SevenZCrackerCPUFactory;

//typedef CrackerFactoryTemplate<SevenZCrackerGPU,vector<SevenZInitData>*, true> SevenZCrackerGPUFactory;

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

uint64_t SevenZFormat::SevenZUINT64(ifstream *stream){
    int bytes = 1;
    uint8_t firstByte;
    
    stream->read(reinterpret_cast<char*>(&firstByte), 1);
//    cout << "firstByte: " << bitset<8>(firstByte) << endl;
    while (firstByte & 0x80){
	SHL(firstByte);
	bytes++;
    }

//    cout << "bytes: " << bytes << endl;
//    cout << "firstByte: " << bitset<8>(firstByte) << endl;
    uint8_t num[bytes];
    num[bytes - 1] = firstByte >> (bytes - 1);    // MSB
    if (bytes > 1)
	stream->read(reinterpret_cast<char*>(&num[0]), bytes-1);

    uint64_t sum = 0;
    for (int i = bytes - 1; i >= 0; i--)	
	sum = ((sum | num[i]) << (i * 8));

    return sum;
}

SevenZStartHdr SevenZFormat::readStartHdr(ifstream *stream){

    SevenZStartHdr header;
    stream->seekg(12,stream->cur);   // 6 signature, 2 version, 4 sigCRC
    stream->read(reinterpret_cast<char*>(&header.NxtHdrOffset),sizeof(uint64_t));
    stream->read(reinterpret_cast<char*>(&header.NxtHdrSize),sizeof(uint64_t));
    stream->seekg(4,stream->cur);   // NextHeaderCRC

    return header;
}

SevenZFolder SevenZFormat::readFolder(ifstream *stream){
    SevenZFolder folder;
    folder.numCoders = SevenZUINT64(stream);
//  cout << "numCoders: " << folder.numCoders << endl;
    folder.coder = new SevenZCoder[folder.numCoders];
    for (uint8_t i = 0; i < folder.numCoders; i++){
	SevenZCoder *coder = &(folder.coder[i]); 
	stream->read(reinterpret_cast<char*>(&coder->flags), 1);
	coder->coderIDSize = (coder->flags & 0x0f);
//	cout << "codec->coderIDSize: " << coder->coderIDSize << endl;
	coder->coderID = new uint8_t[coder->coderIDSize];
	stream->read(reinterpret_cast<char*>(&coder->coderID), coder->coderIDSize);
	// most important and common IDs:
	// 03 01 01 - 7z LZMA
	// 06 f1 07 01 - 7zAES (AES-256 + SHA-256)
	
	if (coder->flags & 0x10){
	    coder->numInStreams = SevenZUINT64(stream);
	    folder.numInStreamsTotal += coder->numInStreams;
//	    cout << "numInStreams: " << coder->numInStreams << endl;
//	    cout << "numInStreamsTotal: " << folder.numInStreamsTotal << endl;

	    coder->numOutStreams = SevenZUINT64(stream);
	    folder.numOutStreamsTotal += coder->numOutStreams;
//	    cout << "numOutStreams: " << coder->numOutStreams << endl;
//	    cout << "numOutStreamsTotal: " << folder.numOutStreamsTotal << endl;
	}else {
	    // TODO: check this in the 7z sources
	    folder.numInStreamsTotal++;
	    folder.numOutStreamsTotal++;
	}
	if (coder->flags & 0x20){
	    coder->propertySize = SevenZUINT64(stream);
//	    cout << "propertySize: " << coder->propertySize << endl;
	    coder->property = new uint8_t[coder->propertySize];
	    stream->read(reinterpret_cast<char*>(&coder->property), coder->propertySize);
	}
//	cout << "coder->flags: " << bitset<8>(coder->flags) << endl;
//    cout << "numInStreamsTotal: " << folder.numOutStreamsTotal << endl;
//    cout << "numOutStreamsTotal: " << folder.numOutStreamsTotal << endl;
    }


    for (uint64_t i = 0; i < (folder.numOutStreamsTotal - 1); i++){
	folder.inIndex = SevenZUINT64(stream);
	folder.outIndex = SevenZUINT64(stream);
    }

    uint64_t numPackStreams = folder.numInStreamsTotal - (folder.numOutStreamsTotal - 1);
//    cout << "numPackStreams: " << numPackStreams << endl;
    if (numPackStreams > 1){
	numPackStreams--;
	folder.index = new uint64_t[numPackStreams];
	for (uint8_t i = 0; i < numPackStreams; i++)	
	    folder.index[i] = SevenZUINT64(stream);
    }
    return folder;
}

uint32_t* SevenZFormat::CRCHdr(ifstream *stream, uint64_t numPackStreams,bool skip){ 
    uint32_t* crc;
    if (!skip)
	crc = new uint32_t[numPackStreams];
    for (uint64_t i = 0; i < numPackStreams; i++){
	uint8_t aad;
	stream->read(reinterpret_cast<char*>(&aad), 1);
	if (aad == 0){
	    cerr << "File reading error. AllAreDefined == 0." << endl;	// TODO: figure out how AAD works
	    exit(153);
	}
	for (uint8_t j = 0; j < aad; j++)
	    if(skip)
		stream->seekg(4, stream->cur);
	    else
		stream->read(reinterpret_cast<char*>(&(crc[j])), 4);  // CRCs[NumDefined]
    }
    return (skip ? NULL : crc);
}

void SevenZFormat::PackInfoHdr(ifstream *stream){	
    SevenZPackInfoHdr *packInfo = new SevenZPackInfoHdr;
    packInfo->packPos = 32 + SevenZUINT64(stream); // offset starting at 0x20 after startHeader
    packInfo->numPackStreams = SevenZUINT64(stream);

    uint8_t subsubHdrID = 1; // we just have to get into the cycle
    while (subsubHdrID != 0){   
	stream->read(reinterpret_cast<char*>(&subsubHdrID), 1);
//	cout << "subsubHdrID: " << bitset<8>(subsubHdrID) << endl;
	if (subsubHdrID == SIZE){   
	    packInfo->packSize = new uint64_t[packInfo->numPackStreams];
	    for (uint64_t i = 0; i < packInfo->numPackStreams; i++)
		packInfo->packSize[i] = SevenZUINT64(stream);
	}else if (subsubHdrID == CRC){
	    packInfo->crc = new uint32_t[packInfo->numPackStreams];
	    for (uint64_t i = 0; i < packInfo->numPackStreams; i++)
		packInfo->crc = CRCHdr(stream, packInfo->numPackStreams, READ);
	}
    }
    data.packInfo = packInfo;
}

void SevenZFormat::CodersHdr(ifstream *stream){	
    uint8_t subsubHdrID;
    stream->read(reinterpret_cast<char*>(&subsubHdrID), 1);	// (FOLDER)
//    cout << "subsubHdrID: " << bitset<8>(subsubHdrID) << endl;

    data.numFolders = SevenZUINT64(stream);
//    cout << "data.numFolders: " << data.numFolders << endl;
    data.folders = new SevenZFolder[data.numFolders];
    uint8_t ext;
    stream->read(reinterpret_cast<char*>(&ext), 1);
    if (ext == 1){
	cerr << "Unsupporte value. External == 1." << endl;	// TODO: add support for work with datastream indexes
	exit(154);
    }else{
	for (uint64_t i = 0; i < data.numFolders; i++)
	    data.folders[i] = readFolder(stream);
    }

    stream->read(reinterpret_cast<char*>(&subsubHdrID), 1);	//(CODERUNPACKSIZE)
//    cout << "subsubHdrID2: " << bitset<8>(subsubHdrID) << endl;
    if (subsubHdrID == CODERUNPACKSIZE){
	for (uint64_t i = 0; i < data.numFolders; i++){
	    data.folders[i].unPackSize = new uint64_t[data.folders[i].numOutStreamsTotal];
//	    cout << "data.numFolders: " << bitset<8>(data.numFolders) << endl;
//	    cout << "numOutStreamsTotal: " << bitset<8>(data.folders[i].numOutStreamsTotal) << endl;
	    for (uint64_t j = 0; j < data.folders[i].numOutStreamsTotal; j++)
	    {
		data.folders[i].unPackSize[j] = SevenZUINT64(stream);
//		cout << "unPackSize: " << bitset<24>(data.folders[i].unPackSize[j]) << endl;
	    }
	}
	stream->read(reinterpret_cast<char*>(&subsubHdrID), 1);	// (CRC)
//	cout << "subsubHdrID3: " << bitset<8>(subsubHdrID) << endl;
    }

    if (subsubHdrID == CRC)	    
	CRCHdr(stream, data.numFolders, SKIP);

    stream->read(reinterpret_cast<char*>(&subsubHdrID), 1);	// (END)

}

void SevenZFormat::readHeader(ifstream *stream){
    uint8_t subHdrID = 1;   // we just wanna get into the cycle
    while (subHdrID != 0){   // End 
	stream->read(reinterpret_cast<char*>(&subHdrID), 1);
//	cout << "subHdrID: " << bitset<8>(subHdrID) << endl;
	if (subHdrID == PACKINFO)
	    PackInfoHdr(stream);
	else if (subHdrID == UNPACKINFO){ 
	    CodersHdr(stream);
	    subHdrID = 0;	// fixed end we have all info we need
//	    stream->read(reinterpret_cast<char*>(&subHdrID), 1);	// END {fileend}
	}
    }
}

void SevenZFormat::readInitInfo(ifstream *stream){

    uint8_t hdrID;
    SevenZStartHdr sighdr = readStartHdr(stream);
    stream->seekg(sighdr.NxtHdrOffset,stream->cur); // move to Main Header
    stream->read(reinterpret_cast<char*>(&hdrID), 1);
//  cout << "hdrID: " << bitset<8>(hdrID) << endl;
    if (hdrID == HDR){
	// raw Main Header 
	// only when only one file is compress and Header is not encrypted
	data.type = RawHeader;
	readHeader(stream); 
    }else if (hdrID == ENCHDR){
	data.type = EncHeader;
	readHeader(stream); 
	// TODO: Decompress and decrypt Main header 
    }


}
void SevenZFormat::init(string& filename){
    ifstream stream;
    stream.open(filename,ios_base::binary);
    char buffer[6];
    data.keyLength = 256;	// there is no other option 
    readInitInfo(&stream);
    
    if (verbose)
	printInfo();
    stream.close();
    is_supported = true;
}
void SevenZFormat::printInfo(){
    cout << "======= SevenZ information =======" << endl;

    if (data.type == NONE)
	cout << "Encryption method is currently not supported by Wrathion." << endl;
    else{
	if (data.type == RawHeader)
	    cout << "Header is not encrypted nor compressed" << endl;
	else if (data.type == EncHeader){
	    if (data.folders[0].numCoders == 1)
		cout << "Header is either compressed or encrypted" << endl;
	    else 
		cout << "Header is compressed and encrypted" << endl;
	}
	cout << "Encryption method: 7ZAES256 + SHA256" << endl;
    } 
    cout << "===============================" << endl;
}
CrackerFactory* SevenZFormat::getCPUCracker(){
//    if(data.type == NONE)
	return NULL;
//    else
//	return new SevenZCrackerCPUFactory(&data);
}

CrackerFactory* SevenZFormat::getGPUCracker(){
//    if(data.type == NONE)
	return NULL;
//    else
//	return new SevenZCrackerGPUFactory(&data);
}

SevenZInitData::SevenZInitData(){
    
}

