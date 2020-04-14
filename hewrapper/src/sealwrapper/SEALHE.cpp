#include "sealwrapper/SEALHE.h"

using namespace hewrapper;

SEALCiphertext::SEALCiphertext& operator=(const SEALCiphertext &b) {
    this->ciphertext = b.ciphertext;
    this->evaluator = b.evaluator;
    return *this;
}

SEALCiphertext::SEALCiphertext operator+(const SEALCiphertext &b) {
    SEALCiphertext tmp;
    tmp.evaluator = this->evaluator;
    this->evaluator.add(this->ciphertext, b.ciphertext, tmp.ciphertext);
    return tmp;
}

SEALCiphertext::SEALCiphertext operator-(const SEALCiphertext &b) {
    SEALCiphertext tmp;
    tmp.evaluator = this->evaluator;
    this->evaluator.sub(this->ciphertext, b.ciphertext, tmp.ciphertext);
    return tmp;
}

SEALCiphertext::SEALCiphertext operator*(const SEALCiphertext &b) {
    SEALCiphertext tmp;
    tmp.evaluator = this->evaluator;
    this->evaluator.multiply(this->ciphertext, b.ciphertext, tmp.ciphertext);
    return tmp;
}

SEALCiphertext::SEALCiphertext operator+(const SEALPlaintext &b) {
    SEALCiphertext tmp;
    tmp.evaluator = this->evaluator;
    this->evaluator.add_plain(this->ciphertext, b.plaintext, tmp.ciphertext);
    return tmp;
}

SEALCiphertext::SEALCiphertext operator-(const SEALPlaintext &b) {
    SEALCiphertext tmp;
    tmp.evaluator = this->evaluator;
    this->evaluator.sub_plain(this->ciphertext, b.plaintext, tmp.ciphertext);
    return tmp;
}

SEALCiphertext::SEALCiphertext operator*(const SEALPlaintext &b) {
    SEALCiphertext tmp;
    tmp.evaluator = this->evaluator;
    this->evaluator.multiply_plain(this->ciphertext, b.plaintext, tmp.ciphertext);
    return tmp;
}

SEALCiphertext::SEALCiphertext& operator+=(const SEALCiphertext &b) {
    this->evaluator.add_inplace(this->ciphertext, b.ciphertext);
    return *this;
}

SEALCiphertext::SEALCiphertext& operator-=(const SEALCiphertext &b) {
    this->evaluator.sub_inplace(this->ciphertext, b.ciphertext);
    return *this;
}

SEALCiphertext::SEALCiphertext& operator*=(const SEALCiphertext &b) {
    this->evaluator.multiply_inplace(this->ciphertext, b.ciphertext);
    return *this;
}

SEALCiphertext::SEALCiphertext& operator+=(const SEALPlaintext &b) {
    this->evaluator.add_plain_inplace(this->ciphertext, b.plaintext);
    return *this;
}

SEALCiphertext::SEALCiphertext& operator-=(const SEALPlaintext &b) {
    this->evaluator.sub_plain_inplace(this->ciphertext, b.plaintext);
    return *this;
}

SEALCiphertext::SEALCiphertext& operator*=(const SEALPlaintext &b) {
    this->evaluator.multiply_plain_inplace(this->ciphertext, b.plaintext);
    return *this;
}