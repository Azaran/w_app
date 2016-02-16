/* 
 * Copyright (C) 2014 Jan Schmied, 2016 Vojtech Vecera
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

#include "Module.h"
#include "ZIPFormat.h"

class ZIPModule: public Module{
public:
    
    virtual std::string getName(){
        return "ZIP";
    }
    
    virtual std::string getAuthor(){
        return "Jan Schmied";
    }
    

    virtual int getBuild(){
        return 1;
    }

    virtual std::string getDescription(){
        return "Module supports cracking ZIP files encrypted with PKZIP stream cipher, AES128, AES192, AES256 and 3DES.";
    }
    

    virtual FileFormat* getFileFormat(){
        return new ZIPFormat();
    }
    

    virtual std::string getVersionText(){
        return "2.0";
    }

};

#ifdef WRATHION_DLL_MODULES
WRATHION_MODULE(ZIPModule)
#endif
