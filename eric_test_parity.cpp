/* eric_test_parity.cpp
 * This is a test of a homomorphic encryption scheme to compute the parity of arbitrarily many variables.
 */

#include "binfhe/binfhecontext.h"
#define SIZE 4096

using namespace lbcrypto;

int main(int argc, char *argv[])
{
    // read inputs from command line
    int n;
    if (argc < 2)
        n = -1;
    else
        n = atoi(argv[1]);
    if (n == -1 || argc < n + 2) {
        std::cout << "Performs a conditional function on n-bit inputs using homomorphic encryption." << std::endl;
        std::cout << "Must provide an integer n followed by n bits to be xor'd." << std::endl;
        return -1;
    }
    LWEPlaintext bits[SIZE];
    for (int i = 0; i < n; i++) {
        bits[i] = atoi(argv[i + 2]);
    }

    // define the cryptocontext.
    auto binFHEContext = BinFHEContext();
    binFHEContext.GenerateBinFHEContext(TOY, AP);
    
    // generate the secret key
    std::cout << "Generating secret key..." << std::endl;
    LWEPrivateKey LWEsk = binFHEContext.KeyGen();
    std::cout << "Done." << std::endl;
    
    // generate the bootstrapping key
    std::cout << "Generating bootstrapping key..." << std::endl;
    binFHEContext.BTKeyGen(LWEsk);
    std::cout << "Done." << std::endl;
    
    std::cout << "Encrypting inputs..." << std::endl;
    LWECiphertext ct[SIZE];
    for (int i = 0; i < n; i++) {
        ct[i] = binFHEContext.Encrypt(LWEsk, bits[i]);
    }
    std::cout << "Done." << std::endl;
    
    std::cout << "Performing computation..." << std::endl;
    LWECiphertext ct_parity = ct[0];
    for (int i = 1; i < n; i++) {
        ct_parity = binFHEContext.EvalBinGate(XOR, ct_parity, ct[i]);
    }

    LWEPlaintext parity;
    binFHEContext.Decrypt(LWEsk, ct_parity, &parity);
    
    std::cout << "Plaintext output: " << parity << std::endl;
    std::cout << "Corresponding ciphertext: " << ct_parity << std::endl;
    
    return 0;
}
