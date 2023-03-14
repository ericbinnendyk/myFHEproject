// Evaluates the following computation homomorphically:
// P(x) = x^3 + 2x + 1 mod 37, where x = 17.
// The result should be 27

#include "openfhe.h"

using namespace lbcrypto;

int main() {
    // Sample Program: Step 1: Set CryptoContext
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(5);// I'm not sure what multiplicative depth is but I think it's the number of times you're able to multiply before you reset.
    // 5 is overkill, but I did it anyway for good measure

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    // Enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    // Sample Program: Step 2: Key Generation

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    // Generate the relinearization key
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);

    // Generate the rotation evaluation keys
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {1, 2, -1, -2});

    // Sample Program: Step 3: Encryption

    // First plaintext VALUE is encoded
    std::vector<int64_t> vectorOfInts = {17};
    Plaintext plaintext_input               = cryptoContext->MakePackedPlaintext(vectorOfInts);
    // Value which is *supposed* to be a constant is encoded
    std::vector<int64_t> one = {1};
    Plaintext plaintext_one = cryptoContext->MakePackedPlaintext(one);

    // The encoded vectors are encrypted
    auto ciphertext_input = cryptoContext->Encrypt(keyPair.publicKey, plaintext_input);
    auto ciphertext_one = cryptoContext->Encrypt(keyPair.publicKey, plaintext_one);

    // Sample Program: Step 4: Evaluation

    // Homomorphic additions and multiplications
    auto ciphertext_input_plus_one     = cryptoContext->EvalAdd(ciphertext_input, ciphertext_one);
    auto ciphertext_two_input_plus_one = cryptoContext->EvalAdd(ciphertext_input, ciphertext_input_plus_one);
    auto ciphertext_input_squared = cryptoContext->EvalMult(ciphertext_input, ciphertext_input);
    auto ciphertext_input_cubed = cryptoContext->EvalMult(ciphertext_input, ciphertext_input_squared);
    auto ciphertext_output = cryptoContext->EvalAdd(ciphertext_two_input_plus_one, ciphertext_input_cubed);

    // decrypt the output
    Plaintext plaintext_output;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertext_output, &plaintext_output);

    std::cout << "Plaintext input: " << plaintext_input << std::endl;
    //char *a;
    //std::cin >> &a >> std::endl;
    //std::cout << "Ciphertext input: " << ciphertext_input << std::endl;
    //std::cout << "Ciphertext output: " << ciphertext_output << std::endl;
    std::cout << "Plaintext output: " << plaintext_output << std::endl;

    return 0;
}
