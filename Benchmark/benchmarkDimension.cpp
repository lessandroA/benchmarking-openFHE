#include "openfhe.h"
#include <unistd.h>
#include <stdlib.h>
#include <fstream>
#include <string>
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "semaphore.h"
#include <stdlib.h>
#include <time.h>   
#include <chrono>
#include <cstdint>


using namespace lbcrypto;

const std::string DATAFOLDER = "ciphertexts";
const std::string fileName = "ciphertext.txt";


int main(int argc, char** argv){

    if(argc < 3)
        return -1;
    
    srand(time(0));


    uint64_t plaintextModulus = atoll(argv[2]);

//    std::cout << "Input:\t" << plaintextModulus << "\t" << multiplicativeDepth << std::endl;


    CryptoContext<DCRTPoly> cryptoContext;


    for(int i = 0; i < 30; i++){

        CCParams<CryptoContextBFVRNS> parameters;
        parameters.SetPlaintextModulus(plaintextModulus);
        parameters.SetMultiplicativeDepth(i + 1);

        CryptoContext<DCRTPoly> cryptoContext;

        cryptoContext = GenCryptoContext(parameters);
        cryptoContext->Enable(PKE);
        cryptoContext->Enable(KEYSWITCH);
        cryptoContext->Enable(LEVELEDSHE);

        // Benchmark for key generation


        KeyPair<DCRTPoly> keyPair;
        keyPair = cryptoContext->KeyGen();
        cryptoContext->EvalMultKeyGen(keyPair.secretKey); // Used in multiplication

        // Benchmark for key dimension

        // Benchmark for encryption
        int64_t xCoord = (rand() % 201) - 100;
        int64_t yCoord = (rand() % 201) - 100;

        std::vector<int64_t> coordVector = {xCoord, yCoord};
        Plaintext coordPlaintext = cryptoContext->MakePackedPlaintext(coordVector);

        std::cout << coordVector << std::endl;


        auto coordCipherText = cryptoContext->Encrypt(keyPair.publicKey, coordPlaintext);    
    
        if (!Serial::SerializeToFile(DATAFOLDER + "/" + fileName, coordCipherText, SerType::BINARY)) {
        std::cerr << "Error writing serialization of ciphertext 1 to ciphertext1.txt" << std::endl;
        return 1;
        }

        std::ifstream file(DATAFOLDER + "/" + fileName, std::ios::binary | std::ios::ate);
        std::uintmax_t size = file.tellg();


        std::ofstream ctDimBenchmark;

        ctDimBenchmark.open("benchmark/cipherTextDimension.txt", std::ios_base::app);
        ctDimBenchmark << size << std::endl; 
    }

    return 0;
}
