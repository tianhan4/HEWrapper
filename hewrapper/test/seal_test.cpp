
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
#include "NetIO.h"

/*
Helper function: Prints a vector of floating-point values.
*/

using namespace std;
using namespace hewrapper;
std::random_device rd;
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
    
    size_t poly_modulus_degree = 16384;
    double standard_scale = 24;
    std::vector<int> coeff_modulus = {50,24,24,24,24,24,24,24,30};
    HWEncryptionParameters parms(poly_modulus_degree,
                    coeff_modulus,
                    seal_scheme::CKKS);
    std::shared_ptr<HWWrapper> engine = make_shared<HWWrapper>();
    engine->init(parms, standard_scale);
    size_t slot_count = engine->slot_count();
    cout <<"Poly modulus degree: " << poly_modulus_degree<< endl;
    cout << "Coefficient modulus: ";
    print_vector<int>(coeff_modulus, coeff_modulus.size());
    cout << endl;
    cout << "slot count: " << slot_count<< endl;
    cout << "scale: " << pow(2.0, 24) << endl;
    
	engine->max_slot() = slot_count;

    HWPlaintext plaintext(engine);
	engine->zero = new HWCiphertext(engine);
	engine->encode(0, plaintext);
	engine->encrypt(plaintext, *(engine->zero));
    engine->lazy_relinearization() = true;
    engine->lazy_mode() = 1;    


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
    engine->encode(2, plain_coeff0);
    engine->encode(3, plain_coeff1);
    engine->encode(-9, plain_coeff2);
    
    HWPlaintext x_plain(engine);
    cout << "Encode input vectors." << endl;
    engine->encode(input, x_plain);

    HWCiphertext x1_encrypted(engine);
    cout << "Encrypt input vectors." << endl;
    engine->encrypt(x_plain, x1_encrypted);

    //the multiply result of two zero ciphertexts
    {
        cout << "multiply result of two zero ciphertexts" << endl;
        HWPlaintext x_p(engine);
        HWCiphertext x_c(engine);
        HWPlaintext y_p(engine);
        HWCiphertext y_c(engine);
        HWCiphertext z_c(engine);
        HWPlaintext plaintext(engine);
        engine->zero = new HWCiphertext(engine);
        engine->encode(0, plaintext);
        engine->encrypt(plaintext, *(engine->zero));
        engine->encode(input, x_p);
        engine->encode(input, y_p);
        engine->encrypt(x_p, x_c);
        engine->encrypt(y_p, y_c);
        cout << "  The result from the multiplication of two non-zero cipehrtexts:" << endl;
        seal_multiply(x_c, y_c, z_c);
        HWPlaintext plain_result(engine);
        engine->decrypt(z_c, plain_result);
        vector<double> result;
        engine->decode(plain_result, result);
        print_vector(result, 3, 7);
        //--------
        cout << "  The result from the multiplication of two zero cipehrtexts:" << endl;
        engine->encrypt(x_p, x_c);
        engine->encrypt(y_p, y_c);
        engine->get_evaluator()->mod_switch_to_inplace(x_c.ciphertext(), engine->get_context()->get_sealcontext()->last_parms_id());
        engine->get_evaluator()->mod_switch_to_inplace(y_c.ciphertext(), engine->get_context()->get_sealcontext()->last_parms_id());
        seal_multiply(x_c, y_c, z_c);
        engine->decrypt(z_c, plain_result);
        engine->decode(plain_result, result);
        print_vector(result, 3, 7);
    }
    
        
/**
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
    seal_multiply_inplace(x2_encrypted, 2);

    cout << "Compute 3x:" << endl;
    seal_multiply_inplace(x1_encrypted, 3);

    cout << "    + Exact scale in 2x^2: " << log2(x2_encrypted.scale()) << endl;
    cout << "    + Exact scale in 3x: " << log2(x1_encrypted.scale()) << endl;
    cout << "    + Exact scale in -9: " << log2(plain_coeff2.scale()) << endl;
    cout << endl;

    cout << "Compute 2x^2 + 3x" << endl;
    seal_add_inplace(x2_encrypted, x1_encrypted);
    cout << "Compute 2x^2 + 3x -9" << endl;
    seal_add_inplace(x2_encrypted, -9);

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
**/
    chrono::high_resolution_clock::time_point time_start, time_end;
    long long count = 100;

    chrono::microseconds time_add_encryption(0);
    chrono::microseconds time_raw_encryption(0);
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

    chrono::microseconds time_decryption_with_nothing(0);
    chrono::microseconds time_decryption_with_rescale(0);
    chrono::microseconds time_decryption_with_relinearization(0);
    chrono::microseconds time_decryption_with_all(0);

    chrono::microseconds time_decryption(0);
    chrono::microseconds time_encryption(0);
    chrono::microseconds time_decode(0);
    chrono::microseconds time_encode(0);
    chrono::microseconds time_rotate_one_step(0);
    chrono::microseconds time_rotate_random(0);
    chrono::microseconds time_rescale(0);
    chrono::microseconds time_relinearization(0);

    
    chrono::microseconds time_modulus_switching_to_zero(0);

    chrono::microseconds time_decryption_zero(0);
    chrono::microseconds time_decode_zero(0);


    cout << "Running pi*x and pi+x for" << count << " times." << endl;
    for ( long long i = 0; i < count ; i ++){
        {//add encryption
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext y_p(engine);
            HWCiphertext y_c(engine);
            HWCiphertext z_c(engine);
            HWPlaintext plaintext(engine);
            engine->zero = new HWCiphertext(engine);
            engine->encode(0, plaintext);
            engine->encrypt(plaintext, *(engine->zero));
            engine->encode(input, x_p);
            engine->encode(input, y_p);
            engine->encrypt(x_p, x_c);
            time_start = chrono::high_resolution_clock::now();
            engine->encrypt(y_p, y_c);
            time_end = chrono::high_resolution_clock::now();
            time_add_encryption += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        }
        
        {//raw encryption
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext y_p(engine);
            HWCiphertext y_c(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encode(input, y_p);
            engine->encrypt(x_p, x_c);
            engine->zero = nullptr;
            time_start = chrono::high_resolution_clock::now();
            engine->encrypt(y_p, y_c);
            time_end = chrono::high_resolution_clock::now();
            time_raw_encryption += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        }
        {//add
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext y_p(engine);
            HWCiphertext y_c(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encode(input, y_p);
            engine->encrypt(x_p, x_c);
            engine->encrypt(y_p, y_c);
            time_start = chrono::high_resolution_clock::now();
            seal_add(x_c, y_c, z_c);
            time_end = chrono::high_resolution_clock::now();
            time_add += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        }
        {//add plain
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext y_p(engine);
            HWCiphertext y_c(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encode(input, y_p);
            engine->encrypt(x_p, x_c);
            engine->encrypt(y_p, y_c);
            time_start = chrono::high_resolution_clock::now();
            seal_add(x_c, y_p, z_c);
            time_end = chrono::high_resolution_clock::now();
            time_add_plain += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        }
        {//add_inplace
            HWPlaintext x_p(engine);
            HWPlaintext z_p(engine);
            HWCiphertext x_c(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encrypt(x_p, x_c);
            engine->encode(input, z_p);
            engine->encrypt(z_p, z_c);
            time_start = chrono::high_resolution_clock::now();
            seal_add_inplace(z_c, x_c);
            time_end = chrono::high_resolution_clock::now();
            time_add_inplace += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        }
        {//add_inplace plain
            HWPlaintext x_p(engine);
            HWPlaintext z_p(engine);
            HWCiphertext x_c(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encrypt(x_p, x_c);
            engine->encode(input, z_p);
            engine->encrypt(z_p, z_c);
            time_start = chrono::high_resolution_clock::now();
            seal_add_inplace(z_c, x_p);
            time_end = chrono::high_resolution_clock::now();
            time_add_plain_inplace += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        }
        {//multi
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext y_p(engine);
            HWCiphertext y_c(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encode(input, y_p);
            engine->encrypt(x_p, x_c);
            engine->encrypt(y_p, y_c);
            time_start = chrono::high_resolution_clock::now();
            seal_multiply(x_c, y_c, z_c);
            time_end = chrono::high_resolution_clock::now();
            time_mul += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        }
        {//multi plain
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext y_p(engine);
            HWCiphertext y_c(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encode(input, y_p);
            engine->encrypt(x_p, x_c);
            engine->encrypt(y_p, y_c);
            time_start = chrono::high_resolution_clock::now();
            seal_multiply(x_c, y_p, z_c);
            time_end = chrono::high_resolution_clock::now();
            time_mul_plain += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        }
        {//multi_inplace
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext z_p(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encrypt(x_p, x_c);
            engine->encode(input, z_p);
            engine->encrypt(z_p, z_c);
            time_start = chrono::high_resolution_clock::now();
            seal_multiply_inplace(z_c, x_c);
            time_end = chrono::high_resolution_clock::now();
            time_mul_inplace += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        }
        {//multi_plain_inplace
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext z_p(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encrypt(x_p, x_c);
            engine->encode(input, z_p);
            engine->encrypt(z_p, z_c);
            time_start = chrono::high_resolution_clock::now();
            seal_multiply_inplace(z_c, x_p);
            time_end = chrono::high_resolution_clock::now();
            time_mul_plain_inplace += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        }
        {//square_inplace
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext y_p(engine);
            HWCiphertext y_c(engine);
            engine->encode(input, x_p);
            engine->encode(input, y_p);
            engine->encrypt(x_p, x_c);
            engine->encrypt(y_p, y_c);
            time_start = chrono::high_resolution_clock::now();
            seal_square_inplace(x_c);
            time_end = chrono::high_resolution_clock::now();
            time_square_inplace += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        }
        {//square
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext y_p(engine);
            HWCiphertext y_c(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encode(input, y_p);
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
            engine->encode(input, x_p);
            engine->encode(input, y_p);
            engine->encrypt(x_p, x_c);
            engine->encrypt(y_p, y_c);
            time_start = chrono::high_resolution_clock::now();
            time_end = chrono::high_resolution_clock::now();
            time_ += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        }
        */

        cout << "Test: Is scalar encoding faster?" << endl;
        {//scalar add
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext y_p(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encrypt(x_p, x_c);
            time_start = chrono::high_resolution_clock::now();
            seal_add(x_c, 1.1, z_c);
            time_end = chrono::high_resolution_clock::now();
            time_scalar_add += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            
            HWPlaintext plain_result(engine);
            engine->decrypt(z_c, plain_result);
            vector<double> result;
            engine->decode(plain_result, result);
            cout << "  Scalar adding 1.1:." << endl;
            print_vector(result, 3, 7);

        }
        
        
        {//scalar-encoding+add
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext y_p(engine);
            HWCiphertext y_c(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encrypt(x_p, x_c);
            time_start = chrono::high_resolution_clock::now();
            engine->encode(2, y_p);
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
        
        {//scalar add inplace
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext y_p(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encrypt(x_p, x_c);
            time_start = chrono::high_resolution_clock::now();
            seal_add_inplace(x_c, 1.1);
            time_end = chrono::high_resolution_clock::now();
            time_scalar_add_inplace += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            
            HWPlaintext plain_result(engine);
            engine->decrypt(x_c, plain_result);
            vector<double> result;
            engine->decode(plain_result, result);
            cout << "  Scalar adding 1.1:." << endl;
            print_vector(result, 3, 7);

        }
        
        
        {//scalar-encoding+add inplace
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext y_p(engine);
            HWCiphertext y_c(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encrypt(x_p, x_c);
            time_start = chrono::high_resolution_clock::now();
            engine->encode(2, y_p);
            seal_add_inplace(x_c, y_p);
            time_end = chrono::high_resolution_clock::now();
            time_no_scalar_add_inplace += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            HWPlaintext plain_result(engine);
            engine->decrypt(x_c, plain_result);
            vector<double> result;
            engine->decode(plain_result, result);
            cout << "  Non-scalar adding 1.1:." << endl;
            print_vector(result, 3, 7);
        }
        

        {//scalar multiply
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext y_p(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encrypt(x_p, x_c);
            time_start = chrono::high_resolution_clock::now();
            seal_multiply(x_c, 2, z_c);
            time_end = chrono::high_resolution_clock::now();
            time_scalar_mul += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            
            HWPlaintext plain_result(engine);
            engine->decrypt(z_c, plain_result);
            vector<double> result;
            engine->decode(plain_result, result);
            cout << "  Scalar multiply 2:" << endl;
            print_vector(result, 3, 7);

        }

        {//scalar-encoding+multiply
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext y_p(engine);
            HWCiphertext y_c(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encrypt(x_p, x_c);
            time_start = chrono::high_resolution_clock::now();
            engine->encode(2, y_p);
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
        
        {//scalar multiply inplace
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext y_p(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encrypt(x_p, x_c);
            time_start = chrono::high_resolution_clock::now();
            seal_multiply_inplace(x_c, 2);
            time_end = chrono::high_resolution_clock::now();
            time_scalar_mul_inplace += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            
            HWPlaintext plain_result(engine);
            engine->decrypt(x_c, plain_result);
            vector<double> result;
            engine->decode(plain_result, result);
            cout << "  Scalar multiply 2:" << endl;
            print_vector(result, 3, 7);

        }

        {//scalar-encoding+multiply inplace
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext y_p(engine);
            HWCiphertext y_c(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encrypt(x_p, x_c);
            time_start = chrono::high_resolution_clock::now();
            engine->encode(2, y_p);
            seal_multiply_inplace(x_c, y_p);
            time_end = chrono::high_resolution_clock::now();
            time_no_scalar_mul_inplace += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            HWPlaintext plain_result(engine);
            engine->decrypt(x_c, plain_result);
            vector<double> result;
            engine->decode(plain_result, result);
            cout << "  Non-scalar mul 2:." << endl;
            print_vector(result, 3, 7);
        }
        cout << "relinearization." << endl;
        // topic: relinearization before decryption?
        {// decryption without anything
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext z_p(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encrypt(x_p, x_c);
            engine->encode(input, z_p);
            engine->encrypt(z_p, z_c);
            seal_multiply_inplace(z_c, x_c);
            time_start = chrono::high_resolution_clock::now();
            engine->decrypt(z_c,z_p);
            time_end = chrono::high_resolution_clock::now();
            time_decryption_with_nothing += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            vector<double> result;
            engine->decode(z_p, result);
            print_vector(result, 3, 7);
        }
        {// relinearization then decryption
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext z_p(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encrypt(x_p, x_c);
            engine->encode(input, z_p);
            engine->encrypt(z_p, z_c);
            seal_multiply_inplace(z_c, x_c);
            time_start = chrono::high_resolution_clock::now();
            engine->get_evaluator()->relinearize_inplace(z_c.ciphertext(), *(engine->get_context()->get_relin_keys()));
            engine->decrypt(z_c,z_p);
            time_end = chrono::high_resolution_clock::now();
            time_decryption_with_relinearization += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            vector<double> result;
            engine->decode(z_p, result);
            print_vector(result, 3, 7);
        }
        {// rescale then decryption
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext z_p(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encrypt(x_p, x_c);
            engine->encode(input, z_p);
            engine->encrypt(z_p, z_c);
            seal_multiply_inplace(z_c, x_c);
            time_start = chrono::high_resolution_clock::now();
            engine->get_evaluator()->rescale_to_next_inplace(z_c.ciphertext());
            engine->decrypt(z_c,z_p);
            time_end = chrono::high_resolution_clock::now();
            time_decryption_with_rescale += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            vector<double> result;
            engine->decode(z_p, result);
            print_vector(result, 3, 7);
        }
        {// relinearization+rescale then decryption
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext z_p(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encrypt(x_p, x_c);
            engine->encode(input, z_p);
            engine->encrypt(z_p, z_c);
            seal_multiply_inplace(z_c, x_c);
            time_start = chrono::high_resolution_clock::now();
            engine->get_evaluator()->relinearize_inplace(z_c.ciphertext(), *(engine->get_context()->get_relin_keys()));
            engine->get_evaluator()->rescale_to_next_inplace(z_c.ciphertext());
            engine->decrypt(z_c,z_p);
            time_end = chrono::high_resolution_clock::now();
            time_decryption_with_all += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            vector<double> result;
            engine->decode(z_p, result);
            print_vector(result, 3, 7);
        }
        // count << "Test 3: Is lazy rescale helpful?" << endl;
        // cout << "Other basic operations" << endl;
        
        {
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext z_p(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encrypt(x_p, x_c);
            engine->encode(input, z_p);
            engine->encrypt(z_p, z_c);
            time_start = chrono::high_resolution_clock::now();
            engine->decrypt(z_c,z_p);
            time_end = chrono::high_resolution_clock::now();
            time_decryption += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            vector<double> result;
            engine->decode(z_p, result);
            print_vector(result, 3, 7);
        }
        {
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext z_p(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encrypt(x_p, x_c);
            engine->encode(input, z_p);
            time_start = chrono::high_resolution_clock::now();
            engine->encrypt(z_p, z_c);
            time_end = chrono::high_resolution_clock::now();
            time_encryption += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            vector<double> result;
            engine->decrypt(z_c,z_p);
            engine->decode(z_p, result);
            print_vector(result, 3, 7);
        }
        {
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            time_start = chrono::high_resolution_clock::now();
            engine->encode(input, x_p);
            time_end = chrono::high_resolution_clock::now();
            time_encode += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        }
        {
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext z_p(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encrypt(x_p, x_c);
            engine->encode(input, z_p);
            engine->encrypt(z_p, z_c);
            engine->decrypt(z_c,z_p);
            vector<double> result;
            time_start = chrono::high_resolution_clock::now();
            engine->decode(z_p, result);
            time_end = chrono::high_resolution_clock::now();
            print_vector(result, 3, 7);
            time_decode += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        }
        {
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            engine->encode(input, x_p);
            engine->encrypt(x_p, x_c);
            time_start = chrono::high_resolution_clock::now();
            engine->get_evaluator()->rotate_vector_inplace(x_c.ciphertext(), 1, *(engine->get_context()->get_galois_keys()));
            engine->get_evaluator()->rotate_vector_inplace(x_c.ciphertext(), -1, *(engine->get_context()->get_galois_keys()));
            time_end = chrono::high_resolution_clock::now();
            time_rotate_one_step += chrono::duration_cast<chrono::microseconds>((time_end - time_start));
        }
        {
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            engine->encode(input, x_p);
            engine->encrypt(x_p, x_c);
            int random_rotation = static_cast<int>(rd() % engine->slot_count());
            time_start = chrono::high_resolution_clock::now();
            engine->get_evaluator()->rotate_vector_inplace(x_c.ciphertext(), random_rotation, *(engine->get_context()->get_galois_keys()));
            time_end = chrono::high_resolution_clock::now();
            time_rotate_random += chrono::duration_cast<chrono::microseconds>((time_end - time_start));
        }

        //cout << "Is zero decryption better?" << endl;
        {
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext z_p(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encrypt(x_p, x_c);
            engine->encode(input, z_p);
            engine->encrypt(z_p, z_c);
            seal_multiply_inplace(z_c, x_c);
            time_start = chrono::high_resolution_clock::now();
            engine->get_evaluator()->mod_switch_to_inplace(z_c.ciphertext(), engine->get_context()->get_sealcontext()->last_parms_id());
            time_end = chrono::high_resolution_clock::now();
            size_t chain_ind1 = engine->get_context()->get_sealcontext()->get_context_data(z_c.ciphertext().parms_id())->chain_index();
            cout << "new_level:" << chain_ind1 << endl;
            time_modulus_switching_to_zero += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        }
        {// rescale
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext z_p(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encrypt(x_p, x_c);
            engine->encode(input, z_p);
            engine->encrypt(z_p, z_c);
            seal_multiply_inplace(z_c, x_c);
            time_start = chrono::high_resolution_clock::now();
            engine->get_evaluator()->rescale_to_next_inplace(z_c.ciphertext());
            time_end = chrono::high_resolution_clock::now();
            time_rescale += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        }
        {// relinearization
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext z_p(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encrypt(x_p, x_c);
            engine->encode(input, z_p);
            engine->encrypt(z_p, z_c);
            seal_multiply_inplace(z_c, x_c);
            time_start = chrono::high_resolution_clock::now();
            engine->get_evaluator()->relinearize_inplace(z_c.ciphertext(), *(engine->get_context()->get_relin_keys()));
            time_end = chrono::high_resolution_clock::now();
            time_relinearization += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        }


        {
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext z_p(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encrypt(x_p, x_c);
            engine->encode(input, z_p);
            engine->encrypt(z_p, z_c);
            engine->get_evaluator()->mod_switch_to_inplace(z_c.ciphertext(), engine->get_context()->get_sealcontext()->last_parms_id());
            time_start = chrono::high_resolution_clock::now();
            engine->decrypt(z_c,z_p);
            time_end = chrono::high_resolution_clock::now();
            time_decryption_zero += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            vector<double> result;
            engine->decode(z_p, result);
            print_vector(result, 3, 7);
        }
        {
            HWPlaintext x_p(engine);
            HWCiphertext x_c(engine);
            HWPlaintext z_p(engine);
            HWCiphertext z_c(engine);
            engine->encode(input, x_p);
            engine->encrypt(x_p, x_c);
            engine->encode(input, z_p);
            engine->encrypt(z_p, z_c);
            engine->get_evaluator()->mod_switch_to_inplace(z_c.ciphertext(), engine->get_context()->get_sealcontext()->last_parms_id());
            engine->decrypt(z_c,z_p);
            vector<double> result;
            time_start = chrono::high_resolution_clock::now();
            engine->decode(z_p, result);
            time_end = chrono::high_resolution_clock::now();
            print_vector(result, 3, 7);
            time_decode_zero += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        }
    }
    auto avg_square = time_square.count()/count;
    auto avg_square_inplace = time_square_inplace.count()/count;

    auto avg_add_encryption = time_add_encryption.count()/count;
    auto avg_raw_encryption = time_raw_encryption.count()/count;
    auto avg_add = time_add.count()/count;
    auto avg_add_inplace = time_add_inplace.count()/count;
    auto avg_add_plain = time_add_plain.count()/count;
    auto avg_add_plain_inplace = time_add_plain_inplace.count()/count;
    auto avg_scalar_add = time_scalar_add.count()/count;
    auto avg_no_scalar_add = time_no_scalar_add.count()/count;
    auto avg_scalar_add_inplace = time_scalar_add_inplace.count()/count;
    auto avg_no_scalar_add_inplace = time_no_scalar_add_inplace.count()/count;

    auto avg_mul = time_mul.count()/count;
    auto avg_mul_inplace = time_mul_inplace.count()/count;
    auto avg_mul_plain_inplace = time_mul_plain_inplace.count()/count;
    auto avg_mul_plain = time_mul_plain.count()/count;
    auto avg_scalar_mul = time_scalar_mul.count()/count;
    auto avg_no_scalar_mul = time_no_scalar_mul.count()/count;
    auto avg_scalar_mul_inplace = time_scalar_mul_inplace.count()/count;
    auto avg_no_scalar_mul_inplace = time_no_scalar_mul_inplace.count()/count;

    auto avg_decryption_with_nothing = time_decryption_with_nothing.count()/count;
    auto avg_decryption_with_rescale = time_decryption_with_rescale.count()/count;
    auto avg_decryption_with_relinearization = time_decryption_with_relinearization.count()/count;
    auto avg_decryption_with_all = time_decryption_with_all.count()/count;

    auto avg_decryption = time_decryption.count()/count;
    auto avg_encryption = time_encryption.count()/count;
    auto avg_encode = time_encode.count()/count;
    auto avg_decode = time_decode.count()/count;
    auto avg_rotate_one_step = time_rotate_one_step.count()/(count * 2);
    auto avg_rotate_random = time_rotate_random.count()/count;
    auto avg_rescale = time_rescale.count()/count;
    auto avg_relinearization = time_relinearization.count()/count;

    auto avg_modulus_switching_to_zero = time_modulus_switching_to_zero.count()/count;

    auto avg_decode_zero = time_decode_zero.count()/count;
    auto avg_decryption_zero = time_decryption_zero.count()/count;

    cout << "Avg square:" << avg_square << "us" << endl;
    cout << "Avg square inplace:" << avg_square_inplace << "us" << endl;
    cout << "Avg add:" << avg_add << "us" << endl;
    cout << "Avg add plain:" << avg_add_plain << "us" << endl;
    cout << "Avg add inplace:" << avg_add_inplace << "us" << endl;
    cout << "Avg add plain inplace:" << avg_add_plain_inplace << "us" << endl;
    cout << "Avg scalar add:" << avg_scalar_add << "us" << endl;
    cout << "Avg scalar add inplace:" << avg_scalar_add_inplace << "us" << endl;
    cout << "Avg non-scalar add:" << avg_no_scalar_add << "us" << endl;
    cout << "Avg non-scalar add inplace:" << avg_no_scalar_add_inplace << "us" << endl;

    cout << "Avg mul:" << avg_mul << "us" << endl;
    cout << "Avg mul plain:" << avg_mul_plain << "us" << endl;
    cout << "Avg mul inplace:" << avg_mul_inplace << "us" << endl;
    cout << "Avg mul plain inplace:" << avg_mul_plain_inplace << "us" << endl;
    cout << "Avg scalar mul:" << avg_scalar_mul << "us" << endl;
    cout << "Avg scalar mul inplace:" << avg_scalar_mul_inplace << "us" << endl;
    cout << "Avg non-scalar mul:" << avg_no_scalar_mul << "us" << endl;
    cout << "Avg non-scalar mul inplace:" << avg_no_scalar_mul_inplace << "us" << endl;

    cout << "Avg raw encryption" << avg_raw_encryption << "us"  << endl;
    cout << "Avg add encryption" << avg_add_encryption << "us"  << endl;

    cout << "Avg decryption with nothing" << avg_decryption_with_nothing << "us"  << endl;
    cout << "Avg decryption with rescale" << avg_decryption_with_rescale << "us"  << endl;
    cout << "Avg decryption with relinearization" << avg_decryption_with_relinearization << "us"  << endl;
    cout << "Avg decryption with all" << avg_decryption_with_all << "us"  << endl;

    cout << "Avg Rescale" << avg_rescale << "us"  << endl;
    cout << "Avg Relinearization" << avg_relinearization << "us"  << endl;

    cout << "Avg rotate one step" << avg_rotate_one_step << "us"  << endl;
    cout << "Avg rorate random" << avg_rotate_random << "us"  << endl;
    cout << "encode" << avg_encode << "us"  << endl;
    cout << "decode" << avg_decode << "us"  << endl;
    cout << "encrypt" << avg_encryption << "us"  << endl;
    cout << "decrypt" << avg_decryption << "us"  << endl;

    
    cout << "decode zero level" << avg_decode_zero << "us"  << endl;
    cout << "decrypt zero level" << avg_decryption_zero << "us"  << endl;

    cout << "modulus swiching to zero level: " << avg_modulus_switching_to_zero << "us" << endl;
    

}

int main() {
    example_ckks_basics();
}
