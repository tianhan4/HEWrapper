#pragma once

#include <memory>
#include <seal/seal.h>
#include "HEBase.h"
#include "sealwrapper/SEALKey.h"
#include "sealwrapper/SEALText.h"

using namespace seal;

namespace hewrapper {

class SEALCiphertext: public HEBase {
public:
    SEALCiphertext(): evaluator(NULL){}

    SEALCiphertext(const SEALEncryptor &k, const SEALPlaintext &val)
    : evaluator(k.evaluator) {
        k.encryptor.encrypt(val.plaintext, ciphertext);
    }

    inline PlainTextBase decrypt(PrivateKeyBase &k) override{
        SEALPlaintext sp;
        static_cast<SEALDecryptor&>(k).decryptor.decrypt(ciphertext, sp.plaintext);
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
    std::shared_ptr<Evaluator> evaluator;
};

} // namespace hewrapper