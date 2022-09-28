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


using namespace lbcrypto;

extern Semaphore publicKeyExchange;
extern Semaphore mutexFile;
extern Semaphore cipherTextExchange;
extern Semaphore mutexCipherTextCounter;
extern Semaphore endOfComputation;
extern int numberOfProcesses;

const std::string DATAFOLDER = "exchangeFolder";


void server(){
    
    publicKeyExchange.acquire();

    mutexFile.acquire();

//    std::cout << "Server acquiring cryptocontext" << std::endl;

    CryptoContext<DCRTPoly> cc;
    if (!Serial::DeserializeFromFile(DATAFOLDER + "/cryptocontext.txt", cc, SerType::BINARY)) {
        std::cerr << "I cannot read serialization from " << DATAFOLDER + "/cryptocontext.txt" << std::endl;
        return;
    }

    mutexFile.release();


    cipherTextExchange.acquire();

//    std::cout << "Server started" << std::endl;

    

    Ciphertext<DCRTPoly> cipherTextSum;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/ciphertext1.txt", cipherTextSum, SerType::BINARY) == false) {
        std::cerr << "Could not read the ciphertext" << std::endl;
        return;
    }


    auto t1 = std::chrono::high_resolution_clock::now();

    for(int i = 1; i < numberOfProcesses; i++){
        std::string index = std::to_string(i + 1);
        Ciphertext<DCRTPoly> tmpCipherText;
        if (Serial::DeserializeFromFile(DATAFOLDER + "/ciphertext" + index +".txt", tmpCipherText, SerType::BINARY) == false) {
            std::cerr << "Could not read the ciphertext" << std::endl;
            return;
        }

        cipherTextSum = cc->EvalAdd(cipherTextSum, tmpCipherText);
    }

    auto t2 = std::chrono::high_resolution_clock::now();

    auto int_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1);

    std::ofstream sumBenchmark;

    sumBenchmark.open("benchmark/sumTime.txt", std::ios_base::app);
    sumBenchmark << numberOfProcesses << std::endl << int_ns.count() << std::endl; 

    if (!Serial::SerializeToFile(DATAFOLDER + "/result.txt", cipherTextSum, SerType::BINARY)) {
        std::cerr << "Error writing serialization of ciperTextSum to result.txt" << std::endl;
        return;
    }

//    std::cout << "Server ended" << std::endl;

    endOfComputation.release();

}