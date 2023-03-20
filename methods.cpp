#include "binfhe/binfhecontext.h"
#include <vector>
#define SIZE 4096

using namespace lbcrypto;

LWECiphertext myEvalGreaterThan(int num_bits, LWECiphertext * ctx, LWECiphertext * cty);
LWECiphertext * myConditional(LWECiphertext ctb, LWECiphertext * ctx, LWECiphertext * cty, int n);
LWECiphertext ** myOrder2(LWECiphertext * cta, LWECiphertext * ctb, int n);
void sort(LWECiphertext ** arr, int len, int num_bits);

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

    LWECiphertext ** pair = myOrder2(cty, ctx, n);
    plaintext_output[0] = -1;
    for (int i = 0; i < n; i++) {
        binFHEContext.Decrypt(LWEsk, pair[0][i], (plaintext_output + i + 1));
    }
    plaintext_output[n+1] = -1;
    
    for (int i = 0; i < n; i++) {
        binFHEContext.Decrypt(LWEsk, pair[1][i], (plaintext_output + i + n + 2));
    }
    
    std::cout << "Plaintext output:" << std::endl;
    for (int i = 0; i < 2*n; i++) {
        std::cout << plaintext_output[i] << std::endl;
    }
    std::cout << "Corresponding ciphertext:" << std::endl;
    for (int i = 0; i < n; i++) {
        std::cout << cond[i] << std::endl;
    }

    // Test out sort().
    LWEPlaintext data[] = {1,0,1, 0,0,1, 1,1,0, 0,1,0, 1,0,0};
    n = 3;
    //len = 5;
    LWECiphertext *ctdata[5];
    for (int i = 0; i < 5; i++) {
        ctdata[i] = (LWECiphertext *) calloc(SIZE, sizeof(LWECiphertext));
        for (int j = 0; j < n; j++) {
            ctdata[i][j] = binFHEContext.Encrypt(LWEsk, data[n*i + j]);
        }
    }
    
    sort(ctdata, 5, n);

    // Here, we read the plaintext output bit by bit.
    std::cout << "Plaintext output:" << std::endl;
    LWEPlaintext curr_plaintext_output;
    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < n; j++) {
            binFHEContext.Decrypt(LWEsk, ctdata[i][j], &curr_plaintext_output);
            std::cout << curr_plaintext_output << std::endl;
        }
    }
    std::cout << "Corresponding ciphertext:" << std::endl;
    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < n; j++) {
            std::cout << ctdata[i][j] << std::endl;
        }
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
        cond[i] = binFHEContext.EvalBinGate(OR, binFHEContext.EvalBinGate(AND, ctx[i], ctb), binFHEContext.EvalBinGate(AND, cty[i], binFHEContext.EvalNOT(ctb)));
    }
    return cond;
}

LWECiphertext ** myOrder2(LWECiphertext * cta, LWECiphertext * ctb, int n) {
    LWECiphertext ** pair = (LWECiphertext **) calloc(SIZE, sizeof(LWECiphertext *));
    LWECiphertext x_1 = myEvalGreaterThan(n, ctb, cta);
    LWECiphertext * s = myConditional(x_1, cta, ctb, n);
    LWECiphertext x_2 = myEvalGreaterThan(n, cta, ctb);
    LWECiphertext * l = myConditional(x_2, cta, ctb, n);
    pair[0] = s;
    pair[1] = l;
    return pair;
}

void sort(LWECiphertext ** arr, int len, int num_bits) {
    for(int i = 1; i < len; i++) {
        for(int j = i - 1; j >= 0; j--) {
            LWECiphertext** pair = myOrder2(arr[j], arr[j+1], num_bits);
            arr[j] = pair[0];
            arr[j+1] = pair[1];
        }
    }
}
