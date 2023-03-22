/* eric_test_addition.cpp
 * This is a test of a homomorphic encryption scheme to compute binary addition of two length-n bitstrings.
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
        std::cout << "Performs binary addition of n-bit inputs using homomorphic encryption." << std::endl;
        std::cout << "Must provide an integer n followed by n bits to be xor'd." << std::endl;
        return -1;
    }
    LWEPlaintext x[SIZE], y[SIZE];
    for (int i = 0; i < n; i++) {
        x[i] = atoi(argv[i + 2]);
        y[i] = atoi(argv[n + i + 2]);
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
    LWECiphertext ctx[SIZE], cty[SIZE];
    for (int i = 0; i < n; i++) {
        ctx[i] = binFHEContext.Encrypt(LWEsk, x[i]);
        cty[i] = binFHEContext.Encrypt(LWEsk, y[i]);
    }
    std::cout << "Done." << std::endl;
    
    std::cout << "Performing computation..." << std::endl;
    LWECiphertext ct_sum[SIZE];
    LWECiphertext ct_sumbit = binFHEContext.EvalBinGate(XOR, ctx[n - 1], cty[n - 1]); // sum of two bits mod 2
    LWECiphertext ct_carry = binFHEContext.EvalBinGate(AND, ctx[n - 1], cty[n - 1]); // value of carry
    ct_sum[n - 1] = ct_sumbit;
    for (int i = n - 2; i >= 0; i--) {
        ct_sumbit = binFHEContext.EvalBinGate(XOR, ctx[i], binFHEContext.EvalBinGate(XOR, cty[i], ct_carry));
        ct_carry = binFHEContext.EvalBinGate(OR, binFHEContext.EvalBinGate(AND, ctx[i], cty[i]), binFHEContext.EvalBinGate(OR, binFHEContext.EvalBinGate(AND, ctx[i], ct_carry), binFHEContext.EvalBinGate(AND, cty[i], ct_carry)));
        ct_sum[i] = ct_sumbit;
    }

    LWEPlaintext sum[SIZE];
    for (int i = 0; i < n; i++) {
        binFHEContext.Decrypt(LWEsk, ct_sum[i], sum + i);
    }
    
    std::cout << "Plaintext output:" << std::endl;
    for (int i = 0; i < n; i++) {
        std::cout << sum[i] << std::endl;
    }
    std::cout << "Corresponding ciphertext:" << std::endl;
    for (int i = 0; i < n; i++) {
        std::cout << ct_sum[i] << std::endl;
    }
    
    return 0;
}
