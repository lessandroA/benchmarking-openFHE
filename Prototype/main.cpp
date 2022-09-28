#include "openfhe.h"
#include <unistd.h>
#include <stdlib.h>
#include <fstream>
#include <thread>
#include <iostream>
#include <mutex>
#include <condition_variable>
#include <string>
// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "semaphore.h"
#include "server_functions.h"

using namespace lbcrypto;

Semaphore publicKeyExchange;
Semaphore mutexFile;
Semaphore cipherTextExchange;
Semaphore mutexCipherTextCounter;
Semaphore endOfComputation;
int cipherTextLoadedInFiles = 0;

int numberOfProcesses;

#include "user_functions.h"
#include "server_functions.h"

int main(int argc, char *argv[])
{

    srand(time(0));


    numberOfProcesses = atoi(argv[1]);

    std::thread children[numberOfProcesses];

    for (int i = 0; i < numberOfProcesses; i++)
    {
        children[i] = std::thread(sendingPosition, i + 1);
    }

    std::thread father(requestingPosition);
    
    std::thread serverThread(server);

    for (int i = 0; i < numberOfProcesses; i++)
    {
        children[i].join();
    }

    father.join();


    serverThread.join();

    return 0;
}