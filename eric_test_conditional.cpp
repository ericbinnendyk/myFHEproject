/* eric_test_conditional.cpp
 * This is a test of a homomorphic encryption scheme to compute the condition function (b, x, y) -> x if b else y, where x and y are length-n Boolean strings.
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
    if (n == -1 || argc < 2*n + 2) {
        std::cout << "Performs a conditional function on n-bit inputs using homomorphic encryption." << std::endl;
        std::cout << "Must provide an integer n followed by 2n + 1 bits: b, x1...xn, and y1...yn." << std::endl;
        return -1;
    }
    LWEPlaintext b;
    LWEPlaintext *x, *y;
    x = (LWEPlaintext *) malloc(n * sizeof(LWEPlaintext));
    y = (LWEPlaintext *) malloc(n * sizeof(LWEPlaintext));
    if (!x || !y) {
        std::cout << "Error: out of memory." << std::endl;
        return -1;
    }
    b = atoi(argv[2]);
    for (int i = 0; i < n; i++) {
        x[i] = atoi(argv[i + 3]);
        y[i] = atoi(argv[i + 3 + n]);
    }

    // define the cryptocontext
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
    // encrypt inputs
    LWECiphertext ctb, ctx[SIZE], cty[SIZE];
    ctb = binFHEContext.Encrypt(LWEsk, b);
    for (int i = 0; i < n; i++) {
        ctx[i] = binFHEContext.Encrypt(LWEsk, x[i]);
        cty[i] = binFHEContext.Encrypt(LWEsk, y[i]);
    }
    std::cout << "Done." << std::endl;

    std::cout << "Performing computation..." << std::endl;
    LWECiphertext cond[SIZE];
    for (int i = 0; i < n; i++) {
        cond[i] = binFHEContext.EvalBinGate(OR, binFHEContext.EvalBinGate(AND, ctx[i], ctb), binFHEContext.EvalBinGate(AND, cty[i], binFHEContext.EvalNOT(ctb)));
    }

    LWEPlaintext plaintext_output[SIZE];
    for (int i = 0; i < n; i++) {
        binFHEContext.Decrypt(LWEsk, cond[i], plaintext_output + i);
    }
    
    std::cout << "Plaintext output:" << std::endl;
    for (int i = 0; i < n; i++) {
        std::cout << plaintext_output[i] << std::endl;
    }
    std::cout << "Corresponding ciphertext:" << std::endl;
    for (int i = 0; i < n; i++) {
        std::cout << cond[i] << std::endl;
    }
    
    return 0;
}
