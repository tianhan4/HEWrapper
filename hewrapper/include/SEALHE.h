#pragma once 

#include <cmath>
#include <cassert>
#include "seal/seal.h"
#include "SEALCtx.h"
#include "SEALEngine.h"
#include "CiphertextWrapper.h"
#include "PlaintextWrapper.h"


namespace hewrapper{

    /*
     * check the scales, if not match, rescale.
     * check the modulus, if not match, match them.
     */

    void seal_square_inplace(SEALCiphertext &arg0);

    void seal_square(const SEALCiphertext &arg0, SEALCiphertext &out);

    void seal_multiply_inplace(SEALCiphertext &arg0, SEALCiphertext &arg1, bool is_parameter = false);

    void seal_multiply_inplace(SEALCiphertext &arg0, SEALPlaintext &arg1);
    
    void seal_multiply_inplace(SEALCiphertext &arg0, double scalar, const seal::MemoryPoolHandle & pool = seal::MemoryManager::GetPool());

    void seal_multiply(const SEALCiphertext &arg0, double scalar, SEALCiphertext &out, const seal::MemoryPoolHandle & pool = seal::MemoryManager::GetPool());

    void seal_multiply(const SEALCiphertext &arg0, SEALCiphertext &arg1, SEALCiphertext &out, bool is_parameter = false);

    void seal_multiply(const SEALCiphertext &arg0, SEALPlaintext &arg1, SEALCiphertext &out);

    void seal_add_inplace(SEALCiphertext &arg0, SEALCiphertext &arg1);

    void seal_add_inplace(SEALCiphertext &arg0, SEALPlaintext &arg1);

    void seal_add(const SEALCiphertext &arg0, SEALCiphertext &arg1, SEALCiphertext &out);

    void seal_add(const SEALCiphertext &arg0, SEALPlaintext &arg1, SEALCiphertext &out);

    void seal_add(const SEALCiphertext &arg0, double scalar, SEALCiphertext &out);

    void seal_add_inplace(SEALCiphertext &arg0, double scalar);
    
    void seal_sub_inplace(SEALCiphertext &arg0, SEALCiphertext &arg1);

    void seal_sub_inplace(SEALCiphertext &arg0, SEALPlaintext &arg1);

    void seal_sub(const SEALCiphertext &arg0, SEALCiphertext &arg1, SEALCiphertext &out);

    void seal_sub(const SEALCiphertext &arg0, SEALPlaintext &arg1, SEALCiphertext &out);

    void seal_sub(const SEALCiphertext &arg0, double scalar, SEALCiphertext &out);

    void seal_sub_inplace(SEALCiphertext &arg0, double scalar);

    void sum_vector(SEALCiphertext &arg0);

    
}
