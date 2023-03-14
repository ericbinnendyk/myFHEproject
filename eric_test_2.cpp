/* eric_test_2.cpp
 * This is a test of a Boolean FHE scheme, the DM scheme, evaluating a simple function.
 */

#include "openfhe.h"
#include "binfhecontext.h"
#include "binfhe-base-scheme.h"

int main()
{
    // First, define the cryptocontext.
    const std::shared_ptr<BinFHECryptoParams> parameters;
    BinFHEContext binFHEContext = BinFHEContext.GenerateBinFHEContext(TOY, DM); // using the parameters recommended for normal users, not used to playing around with parameters
    
    BinFHEScheme scheme = new BinFHEScheme;
    ConstLWEPrivateKey LWEsk = ConstLWEPrivateKey.generate();
    
    RingGSWBTKey key = scheme.KeyGen(parameters);
    
    ConstLWECiphertext ct1 = Encrypt({0});
    ConstLWECiphertext ct2 = Encrypt({1});
    ConstLWECiphertext ct3 = Encrypt({1});
    
    LWECiphertext gate1 = EvalBinGate(parameters, OR, &key, ct1, ct2);
    LWECiphertext gate2 = EvalBinGate(parameters, OR, &key, ct2, ct3);
    LWECiphertext gate3 = EvalBinGate(parameters, AND, &key, gate1, gate2);

    Plaintext plaintext_output;
    cryptoContext->Decrypt(keyPair.secretKey, gate3, &plaintext_output);
    
    std::cout << "Plaintext input: " << {0, 1, 1} << std::endl;
    std::cout << "Plaintext output: " << plaintext_output << std::endl;
    
    return 0;
}
