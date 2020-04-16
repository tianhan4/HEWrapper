#include "test.h"
#include "sealwrapper/SEAL.h"

using namespace std;
using namespace hewrapper;

// Change for other encryption wrappers
typedef SEALEncryptionParameters HWEncryptionParameters;
typedef SEALWrapper HWWrapper;
typedef SEALPlaintext HWPlaintext;
typedef SEALCiphertext HWCiphertext;

/*
    This example follows seal example
    https://github.com/microsoft/SEAL/blob/master/native/examples/4_ckks_basics.cpp
*/
void example_ckks_basics() {
    cout << "ckks demo" << endl;

    HWEncryptionParameters parms(seal_scheme::CKKS);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(poly_modulus_degree, { 60, 40, 40, 60 });

    HWWrapper wrapper;
    wrapper.init(parms);
    auto decryptor = wrapper.get_decryptor();
    auto encryptor = wrapper.get_encryptor();

    size_t slot_count = wrapper.slot_count();
    double scale = pow(2.0, 40);

    // Preapre raw data
    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++, curr_point += step_size)
    {
        input.push_back(curr_point);
    }
    cout << "Input vector: " << endl;
    print_vector(input, 3, 7);

    cout << "Evaluating polynomial PI*x^3 + 0.4x + 1 ..." << endl;
    // Prepare the text
    HWPlaintext plain_coeff3, plain_coeff1, plain_coeff0;
    wrapper.encode(3.14159265, scale, plain_coeff3);
    wrapper.encode(0.4, scale, plain_coeff1);
    wrapper.encode(1.0, scale, plain_coeff0);

    HWPlaintext x_plain;
    print_line(__LINE__);
    cout << "Encode input vectors." << endl;
    wrapper.encode(input, scale, x_plain);

    HWCiphertext x1_encrypted(*encryptor, x_plain);

    print_line(__LINE__);
    cout << "Compute x^2 and relinearize:" << endl;
    HWCiphertext x3_encrypted = x1_encrypted * x1_encrypted;

    cout << "    + Scale of x^2 before rescale (due to lazy rescale): " << log2(x3_encrypted.scale())
        << " bits" << endl;

    print_line(__LINE__);
    cout << "Compute and rescale PI*x." << endl;
    HWCiphertext x1_encrypted_coeff3 = x1_encrypted * plain_coeff3;

    cout << "    + Scale of PI*x before rescale (due to lazy rescale): " << log2(x1_encrypted_coeff3.scale())
        << " bits" << endl;

    print_line(__LINE__);
    cout << "Compute, relinearize, and rescale (PI*x)*x^2." << endl;
    x3_encrypted *= x1_encrypted_coeff3;
    cout << "    + Scale of (PI*x)*x^2 before rescale (due to lazy rescale): " << log2(x3_encrypted.scale())
        << " bits" << endl;

    print_line(__LINE__);
    cout << "Compute and rescale 0.4*x." << endl;
    x1_encrypted *= plain_coeff1;
    cout << "    + Scale of 0.4*x before rescale (due to lazy rescale): " << log2(x1_encrypted.scale())
        << " bits" << endl;
    cout << endl;

    cout << "    + Exact scale in PI*x^3: " << x3_encrypted.scale() << endl;
    cout << "    + Exact scale in  0.4*x: " << x1_encrypted.scale() << endl;
    cout << "    + Exact scale in      1: " << plain_coeff0.scale() << endl;
    cout << endl;

    HWCiphertext encrypted_result = x3_encrypted + x1_encrypted;
    cout << "    + Exact scale in PI*x^3 + 0.4*x: " << encrypted_result.scale() << endl;
    cout << endl;

    encrypted_result += plain_coeff0;

    /*
    First print the true result.
    */
    HWPlaintext plain_result;
    print_line(__LINE__);
    cout << "Decrypt and decode PI*x^3 + 0.4x + 1." << endl;
    cout << "    + Expected result:" << endl;
    vector<double> true_result;
    for (size_t i = 0; i < input.size(); i++)
    {
        double x = input[i];
        true_result.push_back((3.14159265 * x * x + 0.4)* x + 1);
    }
    print_vector(true_result, 3, 7);

    plain_result = encrypted_result.decrypt(*decryptor);
    vector<double> result;
    wrapper.decode(plain_result, result);
    cout << "    + Computed result ...... Correct." << endl;
    print_vector(result, 3, 7);
}

int main() {
    example_ckks_basics();
}