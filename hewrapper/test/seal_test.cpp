
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

/* 
 * Test the average running time of basic operators.
 *
 *
 */
void performance_test(){

    chrono::high_resolution_clock::time_point time_start, timeend;


}

/* 1. basic operation: add, multiply, decode, enncode, encrypt, decrypt/
 * 2. lazy_mode accelerate it.
 * 3. vector inner product
 * 4. activation function: client help
 *
*/
void example_ckks_basics() {
    

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
    engine->encrypt(x_plain, x1_encrypted);

    // check add plain is element-wise add.
    HWCiphertext x3_encrypted(engine);
    HWPlaintext result_tmp(engine);
    seal_add(x1_encrypted, x_plain, x3_encrypted);
    engine->decrypt(x3_encrypted, result_tmp);
    vector<double> output_tmp;
    engine->decode(result_tmp, output_tmp);
    cout << "add plain: " << endl;
    print_vector(output_tmp, 3, 7);


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

    chrono::high_resolution_clock::time_point time_start, time_end;
    long long count = 10;

    chrono::microseconds time_add(0);
    chrono::microseconds time_add_inplace(0);
    chrono::microseconds time_add_plain(0);
    chrono::microseconds time_add_plain_inplace(0);
    chrono::microseconds time_mul(0);
    chrono::microseconds time_mul_inplace(0);
    chrono::microseconds time_mul_plain(0);
    
    chrono::microseconds time_mul_plain_inplace(0);
    chrono::microseconds time_square(0);
    chrono::microseconds time_square_inplace(0);

    chrono::microseconds time_scalar_add(0);
    chrono::microseconds time_scalar_mul(0);
    chrono::microseconds time_no_scalar_add(0);
    chrono::microseconds time_no_scalar_mul(0);
    chrono::microseconds time_scalar_add_inplace(0);
    chrono::microseconds time_scalar_mul_inplace(0);
    chrono::microseconds time_no_scalar_add_inplace(0);
    chrono::microseconds time_no_scalar_mul_inplace(0);

    cout << "Running pi*x and pi+x for" << count << " times." << endl;
    for ( long long i = 0; i < count ; i ++){
        {
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext y_p(engine);
            HWCiphertext y_c(engine);
            engine->encode(input, scale, x_p);
            engine->encode(input, scale, y_p);
            engine->encrypt(x_p, x_c);
            engine->encrypt(y_p, y_c);
            time_start = chrono::high_resolution_clock::now();
            seal_square_inplace(x_c);
            time_end = chrono::high_resolution_clock::now();
            time_square_inplace += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        }
        {
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext y_p(engine);
            HWCiphertext y_c(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, scale, x_p);
            engine->encode(input, scale, y_p);
            engine->encrypt(x_p, x_c);
            engine->encrypt(y_p, y_c);
            time_start = chrono::high_resolution_clock::now();
            seal_square(x_c, z_c);      
            time_end = chrono::high_resolution_clock::now();
            time_square += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        }
        /*
        {
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext y_p(engine);
            HWCiphertext y_c(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, scale, x_p);
            engine->encode(input, scale, y_p);
            engine->encrypt(x_p, x_c);
            engine->encrypt(y_p, y_c);
            time_start = chrono::high_resolution_clock::now();
            time_end = chrono::high_resolution_clock::now();
            time_ += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        }
        */

        cout << "Test: Is scalar encoding faster?" << endl;
        {
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext y_p(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, scale, x_p);
            engine->encrypt(x_p, x_c);
            time_start = chrono::high_resolution_clock::now();
            seal_scalar_add(x_c, 1.1, z_c);
            time_end = chrono::high_resolution_clock::now();
            time_scalar_add += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            
            HWPlaintext plain_result(engine);
            engine->decrypt(z_c, plain_result);
            vector<double> result;
            engine->decode(plain_result, result);
            cout << "  Scalar adding 1.1:." << endl;
            print_vector(result, 3, 7);

        }

        {
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext y_p(engine);
            HWCiphertext y_c(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, scale, x_p);
            engine->encrypt(x_p, x_c);
            time_start = chrono::high_resolution_clock::now();
            engine->encode(1.1, scale, y_p);
            seal_add(x_c, y_p, z_c);
            time_end = chrono::high_resolution_clock::now();
            time_no_scalar_add += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            HWPlaintext plain_result(engine);
            engine->decrypt(z_c, plain_result);
            vector<double> result;
            engine->decode(plain_result, result);
            cout << "  Non-scalar adding 1.1:." << endl;
            print_vector(result, 3, 7);
        }


        {
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext y_p(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, scale, x_p);
            engine->encrypt(x_p, x_c);
            time_start = chrono::high_resolution_clock::now();
            seal_scalar_multiply(x_c, 2, z_c);
            time_end = chrono::high_resolution_clock::now();
            time_scalar_mul += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            
            HWPlaintext plain_result(engine);
            engine->decrypt(z_c, plain_result);
            vector<double> result;
            engine->decode(plain_result, result);
            cout << "  Scalar multiply 2:" << endl;
            print_vector(result, 3, 7);

        }

        {
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext y_p(engine);
            HWCiphertext y_c(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, scale, x_p);
            engine->encrypt(x_p, x_c);
            time_start = chrono::high_resolution_clock::now();
            engine->encode(2, scale, y_p);
            seal_multiply(x_c, y_p, z_c);
            time_end = chrono::high_resolution_clock::now();
            time_no_scalar_mul += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            HWPlaintext plain_result(engine);
            engine->decrypt(z_c, plain_result);
            vector<double> result;
            engine->decode(plain_result, result);
            cout << "  Non-scalar mul 2:." << endl;
            print_vector(result, 3, 7);
        }
        // count << "Test 3: Is lazy rescale helpful?" << endl;


    }
    auto avg_square = time_square.count()/count;
    auto avg_square_inplace = time_square_inplace.count()/count;

    auto avg_scalar_add = time_scalar_add.count()/count;
    auto avg_no_scalar_add = time_no_scalar_add.count()/count;
    auto avg_scalar_mul = time_scalar_mul.count()/count;
    auto avg_no_scalar_mul = time_no_scalar_mul.count()/count;



    cout << "Avg square:" << avg_square << "ms" << endl;
    cout << "Avg square inplace:" << avg_square_inplace << "ms" << endl;
    cout << "Avg scalar add:" << avg_scalar_add << "ms" << endl;
    cout << "Avg non-scalar add:" << avg_no_scalar_add << "ms" << endl;
    cout << "Avg scalar mul:" << avg_scalar_mul << "ms" << endl;
    cout << "Avg non-scalar mul:" << avg_no_scalar_mul << "ms" << endl;


}

int main() {
    example_ckks_basics();
}
