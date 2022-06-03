#include <iostream>
#include <fstream>
#include "cryptopp860/aes.h"
#include "cryptopp860/modes.h"
#include "cryptopp860/filters.h"


// read file clearText.txt and write it to encryptedText.txt
std::string readFile(std::string &fileName) {
    std::ifstream file(fileName);
    if(!file.is_open()) {
        std::cout << "File not found" << std::endl;
        return "";
    }
    return std::string((std::istreambuf_iterator<char>(file)),
                        (std::istreambuf_iterator<char>()));
}


int main(int argc, char* argv[]) {
    std::string fileName = argv[1];
    //std::string key = argv[2];
    std::string clearText = readFile(fileName);
    std::string encryptedText;
    std::string decryptedText;

    //output clearText
    std::cout << "Plain Text (" << clearText.size() << " bytes)" << std::endl;
    std::cout << clearText;
    std::cout << std::endl << std::endl;

    CryptoPP::byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ], iv[ CryptoPP::AES::BLOCKSIZE ];
    memset( key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH );
    memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );

    //create encryptedText
    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv );

    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink( clearText ) );
    stfEncryptor.Put( reinterpret_cast<const unsigned char*>( clearText.c_str() ), clearText.length() );
    stfEncryptor.MessageEnd();

    //output encrypted text
    std::cout << "Cipher Text (" << encryptedText.size() << " bytes)" << std::endl;
    for( int i = 0; i < encryptedText.size(); i++ ) {

        std::cout << "0x" << std::hex << (0xFF & static_cast<CryptoPP::byte>(encryptedText[i])) << " ";
    }
    std::cout << std::endl << std::endl;

    // Decrypt
    CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv );

    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( encryptedText ) );
    stfDecryptor.Put( reinterpret_cast<const unsigned char*>( encryptedText.c_str() ), encryptedText.size() );
    stfDecryptor.MessageEnd();

    //output Decrypted Text
    std::cout << "Decrypted Text: " << std::endl;
    std::cout << decryptedText;
    std::cout << std::endl << std::endl;


    return 0;
}


