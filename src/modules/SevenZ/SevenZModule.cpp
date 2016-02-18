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

#include "Module.h"
#include "SevenZFormat.h"

class SevenZModule: public Module{
public:
    
    virtual std::string getName(){
        return "SevenZ";
    }
    
    virtual std::string getAuthor(){
        return "Vojtech Vecera";
    }
    

    virtual int getBuild(){
        return 1;
    }

    virtual std::string getDescription(){
        return "Module supports cracking 7z files encrypted with 7z AES256 + SHA-256.";
    }
    

    virtual FileFormat* getFileFormat(){
        return new SevenZFormat();
    }
    

    virtual std::string getVersionText(){
        return "2.0";
    }

};

#ifdef WRATHION_DLL_MODULES
WRATHION_MODULE(SevenZModule)
#endif
