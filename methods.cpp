#include "binfhe/binfhecontext.h"
#include <vector>
#include <iostream>
#include <fstream>
#include <stdio.h>      /* printf, scanf, puts, NULL */
#include <stdlib.h>     /* srand, rand */
#include <time.h>       /* time */
#define SIZE 4096
using namespace lbcrypto;

LWECiphertext myEvalGreaterThan(int num_bits, LWECiphertext * ctx, LWECiphertext * cty);
LWECiphertext * myConditional(LWECiphertext ctb, LWECiphertext * ctx, LWECiphertext * cty, int n);
LWECiphertext ** myOrder2(LWECiphertext * cta, LWECiphertext * ctb, int n);
void sort(LWECiphertext ** arr, int len, int num_bits);

auto binFHEContext = BinFHEContext();

int main1(int argc, char * argv[]) {



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

LWECiphertext * myBinaryAddition(LWECiphertext * ctx, LWECiphertext * cty, int n) {
    LWECiphertext * ct_sum = (LWECiphertext *) calloc(SIZE, sizeof(LWECiphertext));
    LWECiphertext ct_sumbit = binFHEContext.EvalBinGate(XOR, ctx[n - 1], cty[n - 1]); // sum of two bits mod 2
    LWECiphertext ct_carry = binFHEContext.EvalBinGate(AND, ctx[n - 1], cty[n - 1]); // value of carry
    ct_sum[n - 1] = ct_sumbit;
    for (int i = n - 2; i >= 0; i--) {
        ct_sumbit = binFHEContext.EvalBinGate(XOR, ctx[i], binFHEContext.EvalBinGate(XOR, cty[i], ct_carry));
        ct_carry = binFHEContext.EvalBinGate(OR, binFHEContext.EvalBinGate(AND, ctx[i], cty[i]), binFHEContext.EvalBinGate(OR, binFHEContext.EvalBinGate(AND, ctx[i], ct_carry), binFHEContext.EvalBinGate(AND, cty[i], ct_carry)));
        ct_sum[i] = ct_sumbit;
    }
    return ct_sum;
}

LWECiphertext* encryptBitstring(LWEPrivateKey LWEsk, LWEPlaintext* pt, int num_bits) {
    LWECiphertext * r = (LWECiphertext*)calloc(num_bits, sizeof(LWECiphertext));
    for(int i = 0; i < num_bits; i++) {
        r[i] = binFHEContext.Encrypt(LWEsk, pt[i]);
    }
    return r;
}

LWEPlaintext* generateRandomArray(int num_bits) {
    LWEPlaintext * r = (LWEPlaintext*)calloc(num_bits, sizeof(LWEPlaintext));
    for(int i = 0; i < num_bits; i++) {
        r[i] = rand() % 2;
    }
    return r;
}

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


 // Experiement for binary addition
    std::ofstream mybinaryadditionFile("../experiments/binaryaddition.csv");
    mybinaryadditionFile << "num_bits,test_number,time_elapsed(ms)" << std::endl;

    for(int test_number = 1; test_number <= 10; test_number++) {
        for(int num_bits = 1; num_bits <= 16; num_bits++) {
            // Generate Encrypted Ciphertexts
            LWECiphertext * ct1 = encryptBitstring(LWEsk, generateRandomArray(num_bits), num_bits);
            LWECiphertext * ct2 = encryptBitstring(LWEsk, generateRandomArray(num_bits), num_bits);

            // Start timer
            auto start = clock();
            myBinaryAddition(ct1, ct2, num_bits);
            auto end = clock();
            double elapsed = double(end - start)/CLOCKS_PER_SEC;
            mybinaryadditionFile << num_bits << "," << test_number << "," << elapsed << std::endl;
        }
    }
    mybinaryadditionFile.close();


    // Experiement for greaterThan
    std::cout << "Starting greaterThan experiment" << std::endl;
    std::ofstream myGTFile("../experiments/greaterthan.csv");
    myGTFile << "num_bits,test_number,time_elapsed(ms)" << std::endl;

    for(int test_number = 1; test_number <= 10; test_number++) {
        for(int num_bits = 1; num_bits <= 16; num_bits++) {
            // Generate Encrypted Ciphertexts
            LWECiphertext * ct1 = encryptBitstring(LWEsk, generateRandomArray(num_bits), num_bits);
            LWECiphertext * ct2 = encryptBitstring(LWEsk, generateRandomArray(num_bits), num_bits);

            // Start timer
            auto start = clock();
            myEvalGreaterThan(num_bits, ct1, ct2);
            auto end = clock();
            double elapsed = double(end - start)/CLOCKS_PER_SEC;
            myGTFile << num_bits << "," << test_number << "," << elapsed << std::endl;
        }
    }
    myGTFile.close();

 
    // Experiement for order2
    std::ofstream myOrder2File("../experiments/order2.csv");
    myOrder2File << "num_bits,test_number,time_elapsed(ms)" << std::endl;

    for(int test_number = 1; test_number <= 10; test_number++) {
        for(int num_bits = 1; num_bits <= 16; num_bits++) {
            // Generate Encrypted Ciphertexts
            LWECiphertext * ct1 = encryptBitstring(LWEsk, generateRandomArray(num_bits), num_bits);
            LWECiphertext * ct2 = encryptBitstring(LWEsk, generateRandomArray(num_bits), num_bits);

            // Start timer
            auto start = clock();
            myOrder2(ct1, ct2, num_bits);
            auto end = clock();
            double elapsed = double(end - start)/CLOCKS_PER_SEC;
            myOrder2File << num_bits << "," << test_number << "," << elapsed << std::endl;
        }
    }
    myOrder2File.close();

   

   
    // Experiement for conditional
    std::ofstream myCondFile("../experiments/conditional.csv");
    myCondFile << "num_bits,test_number,time_elapsed(ms)" << std::endl;
    
    for(int test_number = 1; test_number <= 10; test_number++) {
        for(int num_bits = 1; num_bits <= 16; num_bits++) {
            // Generate Encrypted Ciphertexts
            LWECiphertext * ct1 = encryptBitstring(LWEsk, generateRandomArray(num_bits), num_bits);
            LWECiphertext * ct2 = encryptBitstring(LWEsk, generateRandomArray(num_bits), num_bits);
            auto b = rand() % 2;
            LWECiphertext ctb = binFHEContext.Encrypt(LWEsk, b);

            // Start timer
            auto start = clock();
            myConditional(ctb, ct1, ct2, num_bits);
            auto end = clock();
            double elapsed = double(end - start)/CLOCKS_PER_SEC;
            myCondFile << num_bits << "," << test_number << "," << elapsed << std::endl;
        }
    }
    myCondFile.close();

    // Experiement for sort
    std::cout << "Starting sort experiment" << std::endl;
    std::ofstream mySortFile("../experiments/sort.csv");
    mySortFile << "num_bits,array_length,test_number,time_elapsed" << std::endl;

    for(int test_number = 1; test_number <= 3; test_number++) {
        for(int num_bits = 16; num_bits <= 16; num_bits++) {
            for(int array_length = 2; array_length <= 10; array_length++) {
                LWECiphertext * arr[array_length];
                for(int i = 0; i < array_length; i++) {
                    arr[i] = encryptBitstring(LWEsk, generateRandomArray(num_bits), num_bits);
                }

                // Start timer
                auto start = clock();
                sort(arr, array_length, num_bits);
                auto end = clock();
                double elapsed = double(end - start)/CLOCKS_PER_SEC;
                mySortFile << num_bits << "," << array_length << "," << test_number << "," << elapsed << std::endl;
            }
        }
    }

    mySortFile.close();
   

}
