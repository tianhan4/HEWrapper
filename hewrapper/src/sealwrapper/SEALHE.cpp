#include <cmath>
#include "sealwrapper/SEALHE.h"

using namespace std;
using namespace hewrapper;

void SEALCiphertext::check_and_rescale_cc(SEALCiphertext &b) {
    SEALCiphertext *large_scale_c, *small_scale_c;

    if (this->require_rescale()) {
        this->rescale();
    }
    if (b.require_rescale()) {
        b.rescale();
    }

    if (this->level == b.level)
        return;

    if (this->level < b.level) {
        large_scale_c = &b;
        small_scale_c = this;
    }
    else {
        large_scale_c = this;
        small_scale_c = &b;
    }

    small_scale_c->evaluator->mod_switch_to_inplace(small_scale_c->ciphertext, large_scale_c->ciphertext.parms_id());
    small_scale_c->level = large_scale_c->level;

    small_scale_c->scale() = large_scale_c->scale();
}

void SEALCiphertext::check_and_rescale_cp(SEALPlaintext &b) {
    if (this->require_rescale()) {
            this->rescale();
    }

    if (this->level != 0) {
        this->evaluator->mod_switch_to_inplace(b.plaintext, this->ciphertext.parms_id());
    }
    this->scale() = b.scale();
}

SEALCiphertext& SEALCiphertext::operator=(const SEALCiphertext &b) {
    this->ciphertext = b.ciphertext;
    this->evaluator = b.evaluator;
    this->relin_keys = b.relin_keys;
    this->level = b.level;
    this->lazy_rescale = b.lazy_rescale;
    return *this;
}

SEALCiphertext SEALCiphertext::operator+(SEALCiphertext &b) {
    SEALCiphertext tmp = *this;
    tmp.check_and_rescale_cc(b);
    tmp.evaluator->add_inplace(tmp.ciphertext, b.ciphertext);
    return tmp;
}

SEALCiphertext SEALCiphertext::operator-(SEALCiphertext &b) {
    SEALCiphertext tmp = *this;
    tmp.check_and_rescale_cc(b);
    tmp.evaluator->sub_inplace(tmp.ciphertext, b.ciphertext);
    return tmp;
}

SEALCiphertext SEALCiphertext::operator*(SEALCiphertext &b) {
    SEALCiphertext tmp = *this;
    tmp.check_and_rescale_cc(b);
    tmp.evaluator->multiply_inplace(tmp.ciphertext, b.ciphertext);
    tmp.evaluator->relinearize_inplace(tmp.ciphertext, *(tmp.relin_keys));
    tmp.lazy_rescale = true;
    return tmp;
}

SEALCiphertext SEALCiphertext::operator+(SEALPlaintext &b) {
    SEALCiphertext tmp = *this;
    tmp.check_and_rescale_cp(b);
    tmp.evaluator->add_plain_inplace(tmp.ciphertext, b.plaintext);
    return tmp;
}

SEALCiphertext SEALCiphertext::operator-(SEALPlaintext &b) {
    SEALCiphertext tmp = *this;
    tmp.check_and_rescale_cp(b);
    tmp.evaluator->sub_plain_inplace(tmp.ciphertext, b.plaintext);
    return tmp;
}

SEALCiphertext SEALCiphertext::operator*(SEALPlaintext &b) {
    SEALCiphertext tmp = *this;
    tmp.check_and_rescale_cp(b);
    tmp.evaluator->multiply_plain_inplace(tmp.ciphertext, b.plaintext);
    tmp.lazy_rescale = true;
    return tmp;
}

SEALCiphertext& SEALCiphertext::operator+=(SEALCiphertext &b) {
    check_and_rescale_cc(b);
    this->evaluator->add_inplace(this->ciphertext, b.ciphertext);
    return *this;
}

SEALCiphertext& SEALCiphertext::operator-=(SEALCiphertext &b) {
    check_and_rescale_cc(b);
    this->evaluator->sub_inplace(this->ciphertext, b.ciphertext);
    return *this;
}

SEALCiphertext& SEALCiphertext::operator*=(SEALCiphertext &b) {
    check_and_rescale_cc(b);
    this->evaluator->multiply_inplace(this->ciphertext, b.ciphertext);
    this->evaluator->relinearize_inplace(this->ciphertext, *(this->relin_keys));
    this->lazy_rescale = true;
    return *this;
}

SEALCiphertext& SEALCiphertext::operator+=(SEALPlaintext &b) {
    check_and_rescale_cp(b);
    this->evaluator->add_plain_inplace(this->ciphertext, b.plaintext);
    return *this;
}

SEALCiphertext& SEALCiphertext::operator-=(SEALPlaintext &b) {
    check_and_rescale_cp(b);
    this->evaluator->sub_plain_inplace(this->ciphertext, b.plaintext);
    return *this;
}

SEALCiphertext& SEALCiphertext::operator*=(SEALPlaintext &b) {
    check_and_rescale_cp(b);
    this->evaluator->multiply_plain_inplace(this->ciphertext, b.plaintext);
    this->lazy_rescale = true;
    return *this;
}