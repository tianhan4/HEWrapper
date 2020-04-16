#pragma once

#include <memory>
#include <seal/seal.h>
#include "HEBase.h"
#include "sealwrapper/SEAL.h"

using namespace seal;

namespace hewrapper {

class SEALCiphertext: public HEBase {
public:
    SEALCiphertext(): evaluator(NULL), relin_keys(NULL), level(0), lazy_rescale(false) {}

    SEALCiphertext(const SEALEncryptor &k, const SEALPlaintext &val)
    : evaluator(k.evaluator), relin_keys(k.relin_keys), level(0), lazy_rescale(false) {
        k.encryptor.encrypt(val.plaintext, ciphertext);
    }

    inline PlainTextBase decrypt(PrivateKeyBase &k) override{
        SEALPlaintext sp;
        static_cast<SEALDecryptor&>(k).decryptor.decrypt(ciphertext, sp.plaintext);
        return sp;
    }

    inline SEALPlaintext decrypt(SEALDecryptor &k) {
        SEALPlaintext sp;
        k.decryptor.decrypt(ciphertext, sp.plaintext);
        return sp;
    }

    inline auto &scale() noexcept {
        return ciphertext.scale();
    }

    inline void rescale() {
        evaluator->rescale_to_next_inplace(ciphertext);
        level += 1;
        lazy_rescale = false;
    }

    inline auto get_level() noexcept {
        return level;
    }

    inline auto require_rescale() noexcept {
        return lazy_rescale;
    }

    SEALCiphertext& operator=(const SEALCiphertext &b);
    SEALCiphertext operator+(SEALCiphertext &b);
    SEALCiphertext operator-(SEALCiphertext &b);
    SEALCiphertext operator*(SEALCiphertext &b);
    SEALCiphertext operator+(SEALPlaintext &b);
    SEALCiphertext operator-(SEALPlaintext &b);
    SEALCiphertext operator*(SEALPlaintext &b);

    SEALCiphertext& operator+=(SEALCiphertext &b);
    SEALCiphertext& operator-=(SEALCiphertext &b);
    SEALCiphertext& operator*=(SEALCiphertext &b);
    SEALCiphertext& operator+=(SEALPlaintext &b);
    SEALCiphertext& operator-=(SEALPlaintext &b);
    SEALCiphertext& operator*=(SEALPlaintext &b);

private:
    void check_and_rescale_cc(SEALCiphertext &b);
    void check_and_rescale_cp(SEALPlaintext &b);

    Ciphertext ciphertext;
    std::shared_ptr<Evaluator> evaluator;
    std::shared_ptr<RelinKeys> relin_keys;
    int level; // how many times it has rescaled
    bool lazy_rescale; // we adopt lazy rescale, which means we rescale for this operation on next time
};

} // namespace hewrapper