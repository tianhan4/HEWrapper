#pragma once

#include <memory>
#include <seal/seal.h>
#include "HEBase.h"

using namespace seal;

namespace hewrapper {

class SEALCiphertext: public HEBase {
public:
    friend class SEALEncryptor;
    friend class SEALDecryptor;
    friend class SEALPlaintext;

    SEALCiphertext(): evaluator(NULL){}

    SEALCiphertext(const SEALEncryptor &k, const SEALPlaintext &val)
    : evaluator(k.evaluator) {
        k.encryptor.encrypt(val.plaintext, ciphertext);
    }

    inline SEALPlaintext decrypt(const SEALDecryptor &k) {
        Plaintext p;
        k.decryptor.decrypt(ciphertext, p);
        SEALPlaintext sp;
        sp.plaintext = p;
        return sp;
    }

    SEALCiphertext& operator=(const SEALCiphertext &b);
    SEALCiphertext operator+(const SEALCiphertext &b);
    SEALCiphertext operator-(const SEALCiphertext &b);
    SEALCiphertext operator*(const SEALCiphertext &b);
    SEALCiphertext operator+(const SEALPlaintext &b);
    SEALCiphertext operator-(const SEALPlaintext &b);
    SEALCiphertext operator*(const SEALPlaintext &b);

    SEALCiphertext& operator+=(const SEALCiphertext &b);
    SEALCiphertext& operator-=(const SEALCiphertext &b);
    SEALCiphertext& operator*=(const SEALCiphertext &b);
    SEALCiphertext& operator+=(const SEALPlaintext &b);
    SEALCiphertext& operator-=(const SEALPlaintext &b);
    SEALCiphertext& operator*=(const SEALPlaintext &b);

private:
    Ciphertext ciphertext;
    std::shared_ptr<SEALEvaluator> evaluator;
}

} // namespace hewrapper