/* eric_test_conditional.cpp
 * This is a test of a homomorphic encryption scheme to compute the condition function (b, x, y) -> x if b else y, where x and y are length-n Boolean strings.
 */

#include "binfhe/binfhecontext.h"

using namespace lbcrypto;

int main(int argc, char *argv[])
{
    if (argc < 11) {
        std::cout << "Must provide 11 bits: b, x1...x5, and y1...y5." << std::endl;
        return -1;
    }

    // First, define the cryptocontext.
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

    // read inputs from command line
    LWEPlaintext b, x[5], y[5];
    b = atoi(argv[1]);
    for (int i = 0; i < 5; i++) {
        x[i] = atoi(argv[i + 2]);
        y[i] = atoi(argv[i + 7]);
    }

    std::cout << "Encrypting inputs..." << std::endl;
    // encrypt inputs
    LWECiphertext ctb, ctx[5], cty[5];
    ctb = binFHEContext.Encrypt(LWEsk, b);
    for (int i = 0; i < 5; i++) {
        ctx[i] = binFHEContext.Encrypt(LWEsk, x[i]);
        cty[i] = binFHEContext.Encrypt(LWEsk, y[i]);
    }
    std::cout << "Done." << std::endl;

    std::cout << "Performing computation..." << std::endl;
    LWECiphertext cond[5];
    for (int i = 0; i < 5; i++) {
        cond[i] = binFHEContext.EvalBinGate(OR, binFHEContext.EvalBinGate(AND, ctx[i], ctb), binFHEContext.EvalBinGate(AND, cty[i], binFHEContext.EvalNOT(ctb)));
    }

    LWEPlaintext plaintext_output[5];
    for (int i = 0; i < 5; i++) {
        binFHEContext.Decrypt(LWEsk, cond[i], plaintext_output + i);
    }
    
    std::cout << "Plaintext output:" << std::endl;
    for (int i = 0; i < 5; i++) {
        std::cout << plaintext_output[i] << std::endl;
    }
    std::cout << "Corresponding ciphertext:" << std::endl;
    for (int i = 0; i < 5; i++) {
        std::cout << cond[i] << std::endl;
    }
    
    return 0;
}
