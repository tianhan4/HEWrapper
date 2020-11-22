#pragma once
#include <iostream>
#include <seal/seal.h>
#include "SEALCtx.h"
#include "CiphertextWrapper.h"
#include "PlaintextWrapper.h"
using namespace std;
using namespace hewrapper;

namespace hewrapper {
//*******************************************************************************
// SEALEngine Class is responsible for:
// 1. Maintaining the encryption parameters;
// 2. Generate Ciphertexts and Plaintexts for the application;
//*******************************************************************************
class SEALCiphertext;
class SEALPlaintext;
void seal_add(SEALCiphertext &arg0, SEALPlaintext &arg1, SEALCiphertext &out);
template <typename T>
void replicate_vector(std::vector<T>& vec, size_t final_size);

class SEALEngine : public std::enable_shared_from_this<SEALEngine>{
public:
    SEALEngine(): ctx(NULL), encoder(NULL), encryptor(NULL), decryptor(NULL) {}

    void init(const SEALEncryptionParameters &parms, size_t standard_scale, bool lazy_mode = true, bool auto_mod_switch = true, bool noise_mode = false);
    // 1.
    inline std::shared_ptr<SEALCtx> get_context() const{
        return ctx;
    }

    inline std::shared_ptr<seal::CKKSEncoder> get_encoder() const{
        return encoder;
    }

    inline std::shared_ptr<seal::Encryptor> get_encryptor() const{
        return encryptor;
    }

    inline std::shared_ptr<seal::Decryptor> get_decryptor() const{
        return decryptor;
    }
    inline std::shared_ptr<seal::Evaluator> get_evaluator() const{
        return evaluator;
    }
    bool &lazy_mode(){
            return m_lazy_mode;
    }
    bool const lazy_mode() const{
            return m_lazy_mode;
    }
    
    bool &lazy_relinearization(){
            return m_lazy_relinearization_mode;
    }
    bool const lazy_relinearization() const{
            return m_lazy_relinearization_mode;
    }
    bool &simple_mode(){
            return m_simple_mode;
    }
    bool const simple_mode() const{
            return m_simple_mode;
    }
    bool &auto_mod_switch(){
        return m_auto_mod_switch;
    }
    bool const auto_mod_switch() const{
        return m_auto_mod_switch;
    }
    bool &noise_mode(){
        return m_noise_mode;
    }
    bool const noise_mode() const{
        return m_noise_mode;
    }

    size_t &max_slot(){
        return m_max_slot;
    }
    size_t const max_slot() const{
        return m_max_slot;
    }
    
    inline size_t slot_count() const{
            return encoder->slot_count();
    }
    
    inline double scale() const{
            return this->m_standard_scale;
    }

    // 2.
    inline std::shared_ptr<SEALCiphertext> create_ciphertext(){
            return std::make_shared<SEALCiphertext>(shared_from_this());
    }
    inline std::shared_ptr<SEALPlaintext> create_plaintext(){
            return std::make_shared<SEALPlaintext>(shared_from_this());
    }



    inline void decode(SEALPlaintext &plaintext, std::vector<double> &destination){
        int vector_size = plaintext.size();
        encoder->decode(plaintext.plaintext(), destination);
        destination.resize(vector_size);
        //std::vector<double> sub(destination.cbegin(), destination.cbegin() + plaintext.size());
        //return sub;
    }

    inline void encode(std::vector<double> &values, SEALPlaintext& plaintext){
        encode(values, this->m_standard_scale, plaintext);
        plaintext.init(shared_from_this());
    }
    
    inline void encode(double value, SEALPlaintext& plaintext){
        encode(value, this->m_standard_scale, plaintext);
        plaintext.init(shared_from_this());
    }

    inline void encode(std::vector<double> &values, double scale, SEALPlaintext& plaintext){
        plaintext.size() = values.size();
        auto slot_count = encoder->slot_count();
        if (values.size() > slot_count)
                // number of slots available is poly_modulus_degree / 2
                throw std::invalid_argument(
                "can't encrypt vectors of this size, please use a larger "
                "polynomial modulus degree.");
        replicate_vector(values, slot_count);
        encoder->encode(values, scale, plaintext.plaintext());
        plaintext.init(shared_from_this());
    }


    inline void encode(double value, double scale, SEALPlaintext& plaintext){
        encoder->encode(value, scale, plaintext.plaintext());
        plaintext.size() = 1;
        plaintext.init(shared_from_this());
    }

    inline void encrypt(SEALPlaintext &plaintext, SEALCiphertext& ciphertext){
        if (zero && (&ciphertext!=zero)){
            seal_add(*zero, plaintext, ciphertext);
            ciphertext.clean() = false;
            ciphertext.size() = plaintext.size();
            ciphertext.init(shared_from_this());
            ciphertext.relinearize_required = false;
            ciphertext.rescale_required = false;
        }else{
            encryptor->encrypt(plaintext.plaintext(), ciphertext.ciphertext());
            ciphertext.clean() = false;
            ciphertext.size() = plaintext.size();
            ciphertext.init(shared_from_this());
            ciphertext.relinearize_required = false;
            ciphertext.rescale_required = false;
        }
    }

    inline void decrypt(SEALCiphertext &ciphertext, SEALPlaintext &plaintext){
        if(ciphertext.clean()){
            throw std::invalid_argument("why decrypt a clean ciphertext?");
        }
        //make sure no non-rescaled cophertexts going out.
        //if(this->lazy_mode() && ciphertext.rescale_required){
        //    evaluator->rescale_to_next_inplace(ciphertext.ciphertext());
        //}
        //if(this->lazy_mode() && ciphertext.relinearize_required){
        //    evaluator->relinearize_inplace(ciphertext.ciphertext(), *(ctx->get_relin_keys()));
        //}
        decryptor->decrypt(ciphertext.ciphertext(), plaintext.plaintext());
        plaintext.size() = ciphertext.size();
    }

SEALCiphertext * zero = 0;

private:
    double m_standard_scale;
    size_t m_max_slot;
    bool m_simple_mode = false;
    bool m_lazy_mode;
    bool m_lazy_relinearization_mode;
    bool m_auto_mod_switch;
    bool m_noise_mode;

    std::shared_ptr<SEALCtx> ctx;
    std::shared_ptr<seal::CKKSEncoder> encoder;
    std::shared_ptr<seal::Encryptor> encryptor;
    std::shared_ptr<seal::Decryptor> decryptor;
    std::shared_ptr<seal::Evaluator> evaluator;
}; // class SEALEngine

template <typename T>
void replicate_vector(std::vector<T>& vec, size_t final_size) {
    if (vec.empty()) {
        throw std::invalid_argument("can't replicate an empty vector");
    }
    size_t init_size = vec.size();
    vec.reserve(final_size);
    for (size_t i = 0; i < final_size - init_size; i++) {
        vec.push_back(vec[i % init_size]);
    }
}

} // namespace hewrapper

