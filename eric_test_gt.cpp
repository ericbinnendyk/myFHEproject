/* eric_test_gt.cpp
 * This is a test of a scheme to compute x > y, where x and y are integers represented by binary strings.
 */

#include "binfhe/binfhecontext.h"

using namespace lbcrypto;

int main(int argc, char *argv[])
{
    if (argc < 11) {
        std::cout << "Must provide 10 bits: x1...x5 and y1...y5." << std::endl;
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
    LWEPlaintext x[5], y[5];
    for (int i = 0; i < 5; i++) {
        x[i] = atoi(argv[i + 1]);
        y[i] = atoi(argv[i + 6]);
    }

    std::cout << "Encrypting inputs..." << std::endl;
    // encrypt inputs
    LWECiphertext ctx[5], cty[5];
    for (int i = 0; i < 5; i++) {
        ctx[i] = binFHEContext.Encrypt(LWEsk, x[i]);
        cty[i] = binFHEContext.Encrypt(LWEsk, y[i]);
    }
    std::cout << "Done." << std::endl;

    std::cout << "Performing computation..." << std::endl;
    LWECiphertext differon[5]; // ciphertext explaining the first bit the two inputs differ on
    // We compute differon[i] using an "and" of i + 1 operations. This is done iteratively here, but it could also be done with divide and conquer and result in smaller depth.
    // Formula: (x0 = y0) & (x1 = y1) & ... & (x(i-1) = y(i-1)) & (xi > yi)
    for (int i = 0; i < 5; i++) {
        ConstLWECiphertext test = binFHEContext.EvalNOT(cty[i]);
        differon[i] = binFHEContext.EvalBinGate(AND, ctx[i], test);
        for (int j = 0; j < i; j++) {
            differon[i] = binFHEContext.EvalBinGate(AND, differon[i], binFHEContext.EvalBinGate(XNOR, ctx[j], cty[j]));
        }
    }
    // Now we compute or(differon[i], i=0..n - 1)
    LWECiphertext gt = differon[0];
    for (int i = 1; i < 5; i++) {
        gt = binFHEContext.EvalBinGate(OR, gt, differon[i]);
    }

    LWEPlaintext plaintext_output;
    binFHEContext.Decrypt(LWEsk, gt, &plaintext_output);
    
    std::cout << "Plaintext output: " << plaintext_output << std::endl;
    std::cout << "Corresponding ciphertext: " << gt << std::endl;
    
    return 0;
}
