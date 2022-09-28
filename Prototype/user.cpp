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

extern Semaphore publicKeyExchange;
extern Semaphore mutexFile;
extern Semaphore cipherTextExchange;
extern Semaphore mutexCipherTextCounter;
extern Semaphore endOfComputation;
extern int cipherTextLoadedInFiles;
extern int numberOfProcesses;

const std::string DATAFOLDER = "exchangeFolder";

// Used to calcuate time spent for the Encrypt method, avoiding context switches between threads.
// This semaphore has nothing to do with client-server ored of computations.
Semaphore mutexEncryption; 

void sendingPosition(int i)
{
    std::string indexString = std::to_string(i);

    publicKeyExchange.acquire();
    mutexFile.acquire();

    CryptoContext<DCRTPoly> cc;
    if (!Serial::DeserializeFromFile(DATAFOLDER + "/cryptocontext.txt", cc, SerType::BINARY)) {
        std::cerr << "I cannot read serialization from " << DATAFOLDER + "/cryptocontext.txt" << std::endl;
        return;
    }
//    std::cout << "The cryptocontext has been deserialized." << std::endl;

    PublicKey<DCRTPoly> pk;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/key-public.txt", pk, SerType::BINARY) == false) {
        std::cerr << "Could not read public key" << std::endl;
        return;
    }
//    std::cout << "The public key has been deserialized." << std::endl;

    mutexFile.release();

    // Generate random coordinates

    int64_t xCoord = (rand() % 201) - 100;
    int64_t yCoord = (rand() % 201) - 100;
//    std::cout  << "X: " << xCoord << "\tY: " << yCoord << std::endl;

    std::vector<int64_t> coordinates = {xCoord, yCoord};
    Plaintext coordinatesPlaintext = cc->MakePackedPlaintext(coordinates);

    // Encryption benchmark

    mutexEncryption.acquire();

    auto t1 = std::chrono::high_resolution_clock::now();

    auto coordinatesCiphertext = cc->Encrypt(pk,coordinatesPlaintext);

    auto t2 = std::chrono::high_resolution_clock::now();

    auto int_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1);

    std::ofstream encryptionBenchmark;

    encryptionBenchmark.open("benchmark/encryptionTime.txt", std::ios_base::app);
    encryptionBenchmark << int_ns.count() << std::endl; 


    mutexEncryption.release();

    std::string fileName = "/ciphertext" + indexString + ".txt";

    if (!Serial::SerializeToFile(DATAFOLDER + fileName, coordinatesCiphertext, SerType::BINARY)) {
        std::cerr << "Error writing serialization of ciphertext 1 to ciphertext1.txt" << std::endl;
        return;
    }

    mutexCipherTextCounter.acquire();

    cipherTextLoadedInFiles++;
    // If every user has sent his cipherText, it's possible to unlock the server
    if(cipherTextLoadedInFiles == numberOfProcesses)
        cipherTextExchange.release();

//    std::cout << numberOfProcesses << "\t" << cipherTextLoadedInFiles << std::endl;

    mutexCipherTextCounter.release();
//    std::cout << "Released" << std::endl;

}

void requestingPosition()
{
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(2);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    // Enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

//    std::cout << "\nThe cryptocontext has been generated." << std::endl;

    // Serialize cryptocontext
    if (!Serial::SerializeToFile(DATAFOLDER + "/cryptocontext.txt", cryptoContext, SerType::BINARY)) {
        std::cerr << "Error writing serialization of the crypto context to "
                     "cryptocontext.txt"
                  << std::endl;
        return;
    }
//    std::cout << "The cryptocontext has been serialized." << std::endl;

    // Sample Program: Step 2: Key Generation

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    // std::cout << "The key pair has been generated." << std::endl;

    // Serialize the public key
    if (!Serial::SerializeToFile(DATAFOLDER + "/key-public.txt", keyPair.publicKey, SerType::BINARY)) {
        std::cerr << "Error writing serialization of public key to key-public.txt" << std::endl;
        return;
    }
//    std::cout << "The public key has been serialized." << std::endl;

    for (int i = 0; i <= numberOfProcesses; i++)
    {
        publicKeyExchange.release();
    }
    mutexFile.release();
    mutexCipherTextCounter.release();
    mutexEncryption.release();

    endOfComputation.acquire();

    Ciphertext<DCRTPoly> result;

    if (Serial::DeserializeFromFile(DATAFOLDER + "/result.txt", result, SerType::BINARY) == false) {
        std::cerr << "Could not read the ciphertext" << std::endl;
        return;
    }

    Plaintext ptResult;

    auto t1 = std::chrono::high_resolution_clock::now();

    cryptoContext->Decrypt(keyPair.secretKey, result, &ptResult);

    auto t2 = std::chrono::high_resolution_clock::now();

    auto int_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1);

    std::ofstream decryptionBenchmark;

    decryptionBenchmark.open("benchmark/decryptionTime.txt", std::ios_base::app);
    decryptionBenchmark << int_ns.count() << std::endl; 

    //    ptResult->SetLength(2);

    // std::cout << "Risultato: " << ptResult <<;

    // The vector will store all BFV polynomial coefs
    // We are intersted only in the first two: X and Y sum of values

    std::vector<int64_t> resultVector = ptResult->GetPackedValue();

    std::cout << "Total X: " << resultVector[0] << std::endl;
    std::cout << "Total Y: " << resultVector[1] << std::endl;

    std::cout << "Average X: " << float(resultVector[0]) / float(numberOfProcesses) << std::endl;
    std::cout << "Average Y: " << float(resultVector[1]) / float(numberOfProcesses) << std::endl;
}
