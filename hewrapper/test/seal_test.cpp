
#include <cstddef>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <string>
#include <chrono>
#include <random>
#include <thread>
#include <mutex>
#include <memory>
#include <limits>
#include <algorithm>
#include <numeric>
#include <cmath>
#include "SEALEngine.h"
#include "SEALHE.h"

/*
Helper function: Prints a vector of floating-point values.
*/

using namespace std;
using namespace hewrapper;

// Change for other encryption wrappers
typedef SEALEncryptionParameters HWEncryptionParameters;
typedef SEALEngine HWWrapper;
typedef SEALPlaintext HWPlaintext;
typedef SEALCiphertext HWCiphertext;

template<typename T>
inline void print_vector(std::vector<T> vec, size_t print_size = 4, int prec = 3)
{
    /*
    Save the formatting information for std::cout.
    */
    std::ios old_fmt(nullptr);
    old_fmt.copyfmt(std::cout);

    size_t slot_count = vec.size();

    std::cout << std::fixed << std::setprecision(prec);
    std::cout << std::endl;
    if(slot_count <= 2 * print_size)
    {
        std::cout << "    [";
        for (size_t i = 0; i < slot_count; i++)
        {
            std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    else
    {
        vec.resize(std::max(vec.size(), 2 * print_size));
        std::cout << "    [";
        for (size_t i = 0; i < print_size; i++)
        {
            std::cout << " " << vec[i] << ",";
        }
        if(vec.size() > 2 * print_size)
        {
            std::cout << " ...,";
        }
        for (size_t i = slot_count - print_size; i < slot_count; i++)
        {
            std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    std::cout << std::endl;

    /*
    Restore the old std::cout formatting.
    */
    std::cout.copyfmt(old_fmt);
}

inline void print_line(int line_number)
{
    std::cout << "Line " << std::setw(3) << line_number << " --> ";
}


/* 1. basic operation: add, multiply, decode, enncode, encrypt, decrypt/
 * 2. lazy_mode accelerate it.
 * 3. vector inner product
 * 4. activation function: client help
 *
*/
void example_ckks_basics() {
    
    chrono::high_resolution_clock::time_point time_start, timeend;

    cout << "ckks test" << endl;
    size_t poly_modulus_degree = 8192;
    std::vector<int> coeff_modulus = {60, 40, 40, 60};
    HWEncryptionParameters parms(poly_modulus_degree,
                    coeff_modulus,
                    seal_scheme::CKKS);
    std::shared_ptr<HWWrapper> engine = make_shared<HWWrapper>();
    engine->init(parms, false);
    size_t slot_count = engine->slot_count();
    double scale = pow(2.0, 40);
    cout <<"Poly modulus degree: " << poly_modulus_degree<< endl;
    cout << "Coefficient modulus: ";
    print_vector<int>(coeff_modulus, coeff_modulus.size());
    cout << endl;
    cout << "slot count: " << slot_count<< endl;
    cout << "scale: " << scale << endl;
    
    
    // Preapre raw data
    vector<double> input;
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++, curr_point += step_size)
    {
        input.push_back(curr_point);
    }
    cout << "Input vector: " << endl;
    print_vector(input, 3, 7);

    //basics: calculate 2x^2+3x-9
    // Prepare the text
    HWPlaintext plain_coeff2(engine), plain_coeff1(engine), plain_coeff0(engine);
    engine->encode(2, scale, plain_coeff0);
    engine->encode(3, scale, plain_coeff1);
    engine->encode(-9, scale, plain_coeff2);
    
    HWPlaintext x_plain(engine);
    cout << "Encode input vectors." << endl;
    engine->encode(input, scale, x_plain);

    HWCiphertext x1_encrypted(engine);
    cout << "Encrypt input vectors." << endl;
    engine->encode(input, scale, x_plain);
    engine->encrypt(x_plain, x1_encrypted);

    cout << "Compute x^2" << endl;
    HWCiphertext x2_encrypted(engine);
    seal_square(x1_encrypted, x2_encrypted);

    cout << "Compute 2x^2:" << endl;
    seal_multiply_inplace(x2_encrypted, plain_coeff0);

    cout << "Compute 3x:" << endl;
    seal_multiply_inplace(x1_encrypted, plain_coeff1);

    cout << "    + Exact scale in 2x^2: " << log2(x2_encrypted.scale()) << endl;
    cout << "    + Exact scale in 3x: " << log2(x1_encrypted.scale()) << endl;
    cout << "    + Exact scale in -9: " << log2(plain_coeff2.scale()) << endl;
    cout << endl;

    cout << "Compute 2x^2 + 3x" << endl;
    seal_add_inplace(x2_encrypted, x1_encrypted);
    cout << "Compute 2x^2 + 3x -9" << endl;
    seal_add_inplace(x2_encrypted, plain_coeff2);

    HWPlaintext plain_result(engine);
    vector<double> true_result;
    for (size_t i = 0; i < input.size(); i++)
    {
        double x = input[i];
        true_result.push_back(2*pow(x,2) + 3*x - 9);
    }
    print_vector(true_result, 3, 7);

    engine->decrypt(x2_encrypted, plain_result);
    vector<double> result;
    
    engine->decode(plain_result, result);
    cout << "    + Computed result ...... Correct." << endl;
    print_vector(result, 3, 7);
}

int main() {
    example_ckks_basics();
}
