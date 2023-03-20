#include "binfhe/binfhecontext.h"
#include <vector>
#define SIZE 4096

using namespace lbcrypto;

LWECiphertext myEvalGreaterThan(int num_bits, LWECiphertext * ctx, LWECiphertext * cty);
LWECiphertext * myConditional(LWECiphertext ctb, LWECiphertext * ctx, LWECiphertext * cty, int n);

auto binFHEContext = BinFHEContext();

int main(int argc, char * argv[]) {



    // First, define the cryptocontext.
    binFHEContext.GenerateBinFHEContext(TOY, AP);
    
    // generate the secret key
    std::cout << "Generating secret key..." << std::endl;
    LWEPrivateKey LWEsk = binFHEContext.KeyGen();
    std::cout << "Done." << std::endl;
    
    // generate the bootstrapping key
    std::cout << "Generating bootstrapping key..." << std::endl;
    binFHEContext.BTKeyGen(LWEsk);
    std::cout << "Done." << std::endl;

    int num_bits = 5;
    // LWEPlaintext x[num_bits], y[num_bits];
    std::cout << "Encrypting inputs..." << std::endl;
    // // encrypt inputs
    LWECiphertext ctx[num_bits], cty[num_bits];
    for (int i = 0; i < num_bits; i++) {
        ctx[i] = binFHEContext.Encrypt(LWEsk, 0);
        cty[i] = binFHEContext.Encrypt(LWEsk, 1);
    }
    // std::cout << "Done." << std::endl;
    // LWECiphertext gt = myEvalGreaterThan(5, ctx, cty);
    // LWEPlaintext plaintext_output;
    // binFHEContext.Decrypt(LWEsk, gt, &plaintext_output);
    
    // std::cout << "Plaintext output: " << plaintext_output << std::endl;
    // std::cout << "Corresponding ciphertext: " << gt << std::endl;
    

    int n = 5;
    
    std::cout << "Testing Conditional" << std::endl;
    std::cout << "Encrypting inputs..." << std::endl;
    // encrypt inputs
    int b = 1;
    LWECiphertext ctb = binFHEContext.Encrypt(LWEsk, b);
    LWECiphertext * cond = myConditional(ctb, ctx, cty, n);
    
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

LWECiphertext myEvalGreaterThan(int num_bits, LWECiphertext * ctx, LWECiphertext * cty) {
    LWECiphertext differon[num_bits]; // ciphertext explaining the first bit the two inputs differ on
    // We compute differon[i] using an "and" of i + 1 operations. This is done iteratively here, but it could also be done with divide and conquer and result in smaller depth.
    // Formula: (x0 = y0) & (x1 = y1) & ... & (x(i-1) = y(i-1)) & (xi > yi)
    for (int i = 0; i < num_bits; i++) {
        ConstLWECiphertext test = binFHEContext.EvalNOT(cty[i]);
        differon[i] = binFHEContext.EvalBinGate(AND, ctx[i], test);
        for (int j = 0; j < i; j++) {
            differon[i] = binFHEContext.EvalBinGate(AND, differon[i], binFHEContext.EvalBinGate(XNOR, ctx[j], cty[j]));
        }
    }
    // Now we compute or(differon[i], i=0..n - 1)
    LWECiphertext gt = differon[0];
    for (int i = 1; i < num_bits; i++) {
        gt = binFHEContext.EvalBinGate(OR, gt, differon[i]);
    }
    
    return gt;
}

LWECiphertext * myConditional(LWECiphertext ctb, LWECiphertext * ctx, LWECiphertext * cty, int n) {

    LWECiphertext * cond = (LWECiphertext *) calloc(SIZE, sizeof(LWECiphertext));
    for (int i = 0; i < n; i++) {
        std::cout << i << std::endl;
        cond[i] = binFHEContext.EvalBinGate(OR, binFHEContext.EvalBinGate(AND, ctx[i], ctb), binFHEContext.EvalBinGate(AND, cty[i], binFHEContext.EvalNOT(ctb)));
    }
    return cond;
}