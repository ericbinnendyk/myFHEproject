/* eric_test_2.cpp
 * This is a test of a Boolean FHE scheme, the DM scheme, evaluating a simple function.
 */

//#include "openfhe.h"
#include "binfhe/binfhecontext.h"
//#include "binfhe-base-scheme.h"

using namespace lbcrypto;

int main()
{
    // First, define the cryptocontext.
    //const std::shared_ptr<BinFHECryptoParams> parameters;
    //BinFHEContext binFHEContext = BinFHEContext.GenerateBinFHEContext(TOY, DM); // using the parameters recommended for normal users, not used to playing around with parameters
    auto binFHEContext = BinFHEContext();
    binFHEContext.GenerateBinFHEContext(TOY, AP);
    
    // generate the secret key
    std::cout << "Generating secret key..." << std::endl;
    LWEPrivateKey LWEsk = binFHEContext.KeyGen();
    
    // generate the bootstrapping key
    std::cout << "Generating bootstrapping key..." << std::endl;
    binFHEContext.BTKeyGen(LWEsk);
    
    //RingGSWBTKey key = scheme.KeyGen(parameters);
    
    std::cout << "Plaintext input: " << 0 << 1 << 1 << std::endl;
    ConstLWECiphertext ct1 = binFHEContext.Encrypt(LWEsk, 0);
    ConstLWECiphertext ct2 = binFHEContext.Encrypt(LWEsk, 1);
    ConstLWECiphertext ct3 = binFHEContext.Encrypt(LWEsk, 1);
    
    LWECiphertext gate1 = binFHEContext.EvalBinGate(OR, ct1, ct2);
    LWECiphertext gate2 = binFHEContext.EvalBinGate(OR, ct2, ct3);
    LWECiphertext gate3 = binFHEContext.EvalBinGate(AND, gate1, gate2);

    LWEPlaintext plaintext_output;
    binFHEContext.Decrypt(LWEsk, gate3, &plaintext_output);
    
    std::cout << "Plaintext output: " << plaintext_output << std::endl;
    std::cout << gate3 << std::endl;
    
    return 0;
}
