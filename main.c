#include <stdio.h>
#include <memory.h>
#include <wtypesbase.h>
#include <aes.h>
#include <stdbool.h>

int main() {
//    unsigned char key[16] = { 0 };
//    unsigned char szHeader[256] = { 0 };
//    FILE *file = fopen("C:\\Users\\jelly\\Desktop\\testMac.Key","rb");
    int ires = 0;
    AES_KEY aes_key;
    long long last, lastlen = 0;
    unsigned char key[16] = { 0 };
    unsigned char inbuf[16] = { 0 };
    unsigned char outbuf[16] = { 0 };
    unsigned char szHeader[256] = { 0 };

    FILE *pFile = fopen("C:\\Users\\jelly\\Desktop\\singleMac.Key","rb");
//    fopen_s(&pFile, filename.c_str(), "rb");
    if (!pFile) {
        ires = 1;
        return ires;
    }
    //char *pBuf;
    fseek(pFile, 0, SEEK_END);	//point the file end
    int len = ftell(pFile);
    rewind(pFile);
    //count the decrpt times of file
    ULONG count = (len - 256) / 16;
    if (count <= 0) {
        fclose(pFile);
        ires = 2;
        return ires;
    }
    //get key from file
    if (0 == fread(szHeader, 1, 256, pFile)) {
        fclose(pFile);
        ires = 2;
        return ires;
    }
    memcpy_s(key, 16, szHeader + 100, 16);
    //start to decrpt file
    if (AES_set_decrypt_key(key, 128, &aes_key) == 0){//set decrypt key
        //computer the file size before encrpt
        memcpy_s(inbuf, 16, szHeader, 16);
        AES_decrypt(inbuf, outbuf, &aes_key);
        memcpy_s(&lastlen, sizeof(ULONG), outbuf, sizeof(ULONG));
        last = lastlen % 16; //the part less 16 bytes before encprt
        //check file if the file is able to be decrpted or not
        bool ret = last == 0 ? lastlen == len - 256 : lastlen + 16 - last == len - 256;
        if (!ret)
        {
            fclose(pFile);
            ires = 3;
            return ires;
        }
        FILE *nf = fopen("C:\\Users\\jelly\\Desktop\\singleMac1.Key", "wb+");
//        fopen_s(&nf, newfile.c_str(), "wb+");
        if (!nf) {
            ires = 4;
        } else {
            //decrpt file contents
            for (ULONG k = 0; k < count; k++) {
                SecureZeroMemory(inbuf, 16);
                SecureZeroMemory(outbuf, 16);

                if (0 < fread(inbuf, 1, 16, pFile)){//read 16 bytes from file
                    AES_decrypt(inbuf, outbuf, &aes_key);//decrpt 16 bytes
                    if (k == count - 1) {
                        fwrite(outbuf, 1, last == 0 ? 16 : last, nf);
//                        printf(outbuf);
                    } else {
                        fwrite(outbuf, 1, 16, nf);
//                        printf(outbuf);
                    }
                }
            }
            fclose(nf);
        }
        fclose(pFile);
//        DeleteFileA(filename.c_str());
//        FileRename(newfile, filename);
    } else {
        fclose(pFile);
    }
    return ires;
//    return 0;
}