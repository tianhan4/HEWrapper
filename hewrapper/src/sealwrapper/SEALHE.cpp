#include <cmath>
#include "sealwrapper/SEALHE.h"

using namespace std;
using namespace hewrapper;

void check_and_rescale(SEALCiphertext &a, SEALCiphertext &b) {
    SEALCiphertext *large_scale_c, *small_scale_c;

    if (a.require_rescale()) {
        a.rescale();
    }
    if (b.require_rescale()) {
        b.rescale();
    }

    else if (a.get_level() > b.get_level()) {
        large_scale_c = &a;
        small_scale_c = &b;
    }
    else {
        large_scale_c = &b;
        small_scale_c = &a;
    }

    while (fabs(log2(small_scale_c->scale()) - log2(large_scale_c->scale())) > 1 
            && small_scale_c->get_level() < large_scale_c->get_level()) {
        small_scale_c->rescale();
    }
}

SEALCiphertext& SEALCiphertext::operator=(const SEALCiphertext &b) {
    this->ciphertext = b.ciphertext;
    this->evaluator = b.evaluator;
    this->relin_keys = b.relin_keys;
    this->level = b.level;
    this->require_rescale = b.require_rescale;
    return *this;
}

SEALCiphertext SEALCiphertext::operator+(SEALCiphertext &b) {
    SEALCiphertext tmp = *this;
    check_and_rescale(tmp, b);
    tmp.evaluator->add_inplace(tmp.ciphertext, b.ciphertext);
    return tmp;
}

SEALCiphertext SEALCiphertext::operator-(SEALCiphertext &b) {
    SEALCiphertext tmp = *this;
    check_and_rescale(tmp, b);
    tmp.evaluator->sub_inplace(tmp.ciphertext, b.ciphertext);
    return tmp;
}

SEALCiphertext SEALCiphertext::operator*(SEALCiphertext &b) {
    SEALCiphertext tmp = *this;
    check_and_rescale(tmp, b);
    tmp.evaluator->multiply_inplace(tmp.ciphertext, b.ciphertext);
    tmp.evaluator->relinearize_inplace(tmp.ciphertext, *(tmp.relin_keys));
    tmp.level += 1;
    tmp.rescale = true;
    return tmp;
}

SEALCiphertext SEALCiphertext::operator+(const SEALPlaintext &b) {
    SEALCiphertext tmp = *this;
    tmp.evaluator->add_plain_inplace(tmp.ciphertext, b.plaintext);
    return tmp;
}

SEALCiphertext SEALCiphertext::operator-(const SEALPlaintext &b) {
    SEALCiphertext tmp = *this;
    tmp.evaluator->sub_plain_inplace(tmp.ciphertext, b.plaintext);
    return tmp;
}

SEALCiphertext SEALCiphertext::operator*(const SEALPlaintext &b) {
    SEALCiphertext tmp = *this;
    if (tmp.require_rescale()) {
        tmp.rescale();
    }
    tmp.evaluator->multiply_plain_inplace(tmp.ciphertext, b.plaintext);
    tmp.level += 1;
    tmp.rescale = true;
    return tmp;
}

SEALCiphertext& SEALCiphertext::operator+=(SEALCiphertext &b) {
    check_and_rescale(*this, b);
    this->evaluator->add_inplace(this->ciphertext, b.ciphertext);
    return *this;
}

SEALCiphertext& SEALCiphertext::operator-=(SEALCiphertext &b) {
    check_and_rescale(*this, b);
    this->evaluator->sub_inplace(this->ciphertext, b.ciphertext);
    return *this;
}

SEALCiphertext& SEALCiphertext::operator*=(SEALCiphertext &b) {
    check_and_rescale(*this, b);
    this->evaluator->multiply_inplace(this->ciphertext, b.ciphertext);
    this->evaluator->relinearize_inplace(this->ciphertext, *(this.relin_keys));
    this->level += 1;
    this.rescale = true;
    return *this;
}

SEALCiphertext& SEALCiphertext::operator+=(const SEALPlaintext &b) {
    this->evaluator->add_plain_inplace(this->ciphertext, b.plaintext);
    return *this;
}

SEALCiphertext& SEALCiphertext::operator-=(const SEALPlaintext &b) {
    this->evaluator->sub_plain_inplace(this->ciphertext, b.plaintext);
    return *this;
}

SEALCiphertext& SEALCiphertext::operator*=(const SEALPlaintext &b) {
    if (this->require_rescale()) {
        this->rescale();
    }
    this->evaluator->multiply_plain_inplace(this->ciphertext, b.plaintext);
    this->level += 1;
    this.rescale = true;
    return *this;
}