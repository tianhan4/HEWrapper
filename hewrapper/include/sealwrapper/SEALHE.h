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
    SEALCiphertext(): evaluator(NULL), relin_keys(NULL), level(0), require_rescale(false) {}

    SEALCiphertext(const SEALEncryptor &k, const SEALPlaintext &val)
    : evaluator(k.evaluator), relin_keys(k.relin_keys), level(0), require_rescale(false) {
        k.encryptor.encrypt(val.plaintext, ciphertext);
    }

    inline PlainTextBase decrypt(PrivateKeyBase &k) override{
        SEALPlaintext sp;
        static_cast<SEALDecryptor&>(k).decryptor.decrypt(ciphertext, sp.plaintext);
        return sp;
    }

    inline auto &scale() noexcept {
        return ciphertext.scale();
    }

    inline void rescale() {
        evaluator->rescale_to_next_inplace(ciphertext);
        level += 1;
        rescale = false;
    }

    inline auto get_level() noexcept {
        return level;
    }

    inline auto require_rescale() noexcept {
        return rescale;
    }

    SEALCiphertext& operator=(const SEALCiphertext &b);
    SEALCiphertext operator+(SEALCiphertext &b);
    SEALCiphertext operator-(SEALCiphertext &b);
    SEALCiphertext operator*(SEALCiphertext &b);
    SEALCiphertext operator+(const SEALPlaintext &b);
    SEALCiphertext operator-(const SEALPlaintext &b);
    SEALCiphertext operator*(const SEALPlaintext &b);

    SEALCiphertext& operator+=(SEALCiphertext &b);
    SEALCiphertext& operator-=(SEALCiphertext &b);
    SEALCiphertext& operator*=(SEALCiphertext &b);
    SEALCiphertext& operator+=(const SEALPlaintext &b);
    SEALCiphertext& operator-=(const SEALPlaintext &b);
    SEALCiphertext& operator*=(const SEALPlaintext &b);

private:
    Ciphertext ciphertext;
    std::shared_ptr<Evaluator> evaluator;
    std::shared_ptr<RelinKeys> relin_keys;
    int level; // how many times it has rescaled
    bool rescale; // we adopt lazy rescale, which means we rescale for this operation on next time
};

} // namespace hewrapper