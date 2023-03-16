/* eric_test_parity.cpp
 * This is a test of a scheme to compute the parity of ~~arbitrarily many variables~~ currently three variables.
 */

#include "binfhe/binfhecontext.h"

using namespace lbcrypto;

int main(int argc, char *argv[])
{
    if (argc < 4) {
        std::cout << "Must provide three bits to be xor'd." << std::endl;
        return -1;
    }

    // First, define the cryptocontext.
    auto binFHEContext = BinFHEContext();
    binFHEContext.GenerateBinFHEContext(TOY, AP);
    
    // generate the secret key
    std::cout << "Generating secret key..." << std::endl;
    LWEPrivateKey LWEsk = binFHEContext.KeyGen();
    
    // generate the bootstrapping key
    std::cout << "Generating bootstrapping key..." << std::endl;
    binFHEContext.BTKeyGen(LWEsk);
    
    LWEPlaintext bits[3];
    for (int i = 0; i < 3; i++) {
        bits[i] = atoi(argv[i + 1]);
    }
    ConstLWECiphertext ct1 = binFHEContext.Encrypt(LWEsk, bits[0]);
    ConstLWECiphertext ct2 = binFHEContext.Encrypt(LWEsk, bits[1]);
    ConstLWECiphertext ct3 = binFHEContext.Encrypt(LWEsk, bits[2]);
    
    LWECiphertext xor1 = binFHEContext.EvalBinGate(XOR, ct1, ct2);
    LWECiphertext xor2 = binFHEContext.EvalBinGate(XOR, xor1, ct3);

    LWEPlaintext plaintext_output;
    binFHEContext.Decrypt(LWEsk, xor2, &plaintext_output);
    
    std::cout << "Plaintext output: " << plaintext_output << std::endl;
    std::cout << "Corresponding ciphertext: " << xor2 << std::endl;
    
    return 0;
}
