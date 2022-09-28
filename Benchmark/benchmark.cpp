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

using namespace lbcrypto;

const std::string DATAFOLDER = "exchangeFolder";


int main(int argc, char** argv){

    if(argc < 3)
        return -1;
    
    srand(time(0));

    int iterations = atoi(argv[1]);

    uint64_t plaintextModulus = atoll(argv[2]);
    uint32_t multiplicativeDepth = atoi(argv[3]);

//    std::cout << "Input:\t" << plaintextModulus << "\t" << multiplicativeDepth << std::endl;

    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(plaintextModulus);
    parameters.SetMultiplicativeDepth(multiplicativeDepth);

    CryptoContext<DCRTPoly> cryptoContext;


    for(int i = 0; i < iterations; i++){

        cryptoContext = GenCryptoContext(parameters);
        cryptoContext->Enable(PKE);
        cryptoContext->Enable(KEYSWITCH);
        cryptoContext->Enable(LEVELEDSHE);

        // Benchmark for key generation

        auto t1 = std::chrono::high_resolution_clock::now();

        KeyPair<DCRTPoly> keyPair;
        keyPair = cryptoContext->KeyGen();
        cryptoContext->EvalMultKeyGen(keyPair.secretKey); // Used in multiplication

        auto t2 = std::chrono::high_resolution_clock::now();

        auto int_ns_keyGen = std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1);

        std::ofstream keyGenBenchmark;

        keyGenBenchmark.open("benchmark/keyGenTime_" + std::to_string(plaintextModulus) + "_" + std::to_string(multiplicativeDepth) + ".txt", std::ios_base::app);
        keyGenBenchmark << int_ns_keyGen.count() << std::endl; 

        // Benchmark for key dimension

        if (!Serial::SerializeToFile(DATAFOLDER + "/key-private_" + std::to_string(plaintextModulus) + "_" + std::to_string(multiplicativeDepth) + "_" + std::to_string(i) + ".txt", keyPair.secretKey, SerType::BINARY)) {
            std::cerr << "Error writing serialization of private key to key-private.txt" << std::endl;
            return 1;
        }
//        std::cout << "The secret key has been serialized." << std::endl;

        // Benchmark for encryption
        int64_t xCoord = (rand() % 201) - 100;
        int64_t yCoord = (rand() % 201) - 100;

        std::vector<int64_t> coordVector = {xCoord, yCoord};
        Plaintext coordPlaintext = cryptoContext->MakePackedPlaintext(coordVector);

//        std::cout << coordVector << std::endl;

        auto t3 = std::chrono::high_resolution_clock::now();

        auto coordCipherText = cryptoContext->Encrypt(keyPair.publicKey, coordPlaintext);    
    
        auto t4 = std::chrono::high_resolution_clock::now();

        auto int_ns_encryption = std::chrono::duration_cast<std::chrono::nanoseconds>(t4 - t3);
        
        std::ofstream encryptionBenchmark;

        encryptionBenchmark.open("benchmark/encryptionTime_" + std::to_string(plaintextModulus) + "_" + std::to_string(multiplicativeDepth) + ".txt", std::ios_base::app);
        encryptionBenchmark << int_ns_encryption.count() << std::endl; 


        int64_t xCoordAux = (rand() % 201) - 100;
        int64_t yCoordAux = (rand() % 201) - 100;

        std::vector<int64_t> coordVectorAux = {xCoordAux, yCoordAux};
//        std::cout << coordVectorAux << std::endl;

        Plaintext coordPlaintextAux = cryptoContext->MakePackedPlaintext(coordVectorAux);
        auto coordCipherTextAux = cryptoContext->Encrypt(keyPair.publicKey, coordPlaintextAux);    

        // Benchmark for sum of two vectors

        auto t5 = std::chrono::high_resolution_clock::now();

        auto ciphertextSum = cryptoContext->EvalAdd(coordCipherText, coordCipherTextAux);
    
        auto t6 = std::chrono::high_resolution_clock::now();

        auto int_ns_sum = std::chrono::duration_cast<std::chrono::nanoseconds>(t6 - t5);

        std::ofstream sumBenchmark;

        sumBenchmark.open("benchmark/sumTime_" + std::to_string(plaintextModulus) + "_" + std::to_string(multiplicativeDepth) + ".txt", std::ios_base::app);
        sumBenchmark << int_ns_sum.count() << std::endl; 

        // Benchmark for multiplication of two vectors     
        
        auto t7 = std::chrono::high_resolution_clock::now();

        auto ciphertextMultiplication = cryptoContext->EvalMult(coordCipherText, coordCipherTextAux);
    
        auto t8 = std::chrono::high_resolution_clock::now();

        auto int_ns_mult = std::chrono::duration_cast<std::chrono::nanoseconds>(t8 - t7);

        std::ofstream multBenchmark;

        multBenchmark.open("benchmark/multTime_" + std::to_string(plaintextModulus) + "_" + std::to_string(multiplicativeDepth) + ".txt", std::ios_base::app);
        multBenchmark << int_ns_mult.count() << std::endl; 

        // Benchmark for decryption

        Plaintext sumPlaintext;
        Plaintext multPlaintext;

        auto t9 = std::chrono::high_resolution_clock::now();

        cryptoContext->Decrypt(keyPair.secretKey, ciphertextSum, &sumPlaintext);

        auto t10 = std::chrono::high_resolution_clock::now();

        std::ofstream decryptionBenchmark;

        auto int_ns_decryption = std::chrono::duration_cast<std::chrono::nanoseconds>(t10 - t9);

        decryptionBenchmark.open("benchmark/decryptionTime_" + std::to_string(plaintextModulus) + "_" + std::to_string(multiplicativeDepth) + ".txt", std::ios_base::app);
        decryptionBenchmark << int_ns_decryption.count() << std::endl; 

        cryptoContext->Decrypt(keyPair.secretKey, ciphertextMultiplication, &multPlaintext);
        
//        std::cout << sumPlaintext << std::endl;
//        std::cout << multPlaintext << std::endl;

    }

    return 0;
}