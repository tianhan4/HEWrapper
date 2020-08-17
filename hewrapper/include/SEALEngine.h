#pragma once
#include <seal/seal.h>
#include "SEALCtx.h"
#include "CiphertextWrapper.h"
#include "PlaintextWrapper.h"

namespace hewrapper {
//*******************************************************************************
// SEALEngine Class is responsible for:
// 1. Maintaining the encryption parameters;
// 2. Generate Ciphertexts and Plaintexts for the application;
//*******************************************************************************
class SEALCiphertext;
class SEALPlaintext;
class SEALEngine : std::enable_shared_from_this<SEALEngine>{
public:
    SEALEngine(): ctx(NULL), encoder(NULL), encryptor(NULL), decryptor(NULL) {}

    void init(const SEALEncryptionParameters &parms, bool lazy_mode);
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
    bool lazy_mode() const{
            return m_lazy_mode;
    }
    bool &simple_mode(){
            return m_simple_mode;
    }
    bool simple_mode() const{
            return m_simple_mode;
    }


    // 2.
    inline std::shared_ptr<SEALCiphertext> create_ciphertext(){
            return std::make_shared<SEALCiphertext>(shared_from_this());
    }
    inline std::shared_ptr<SEALPlaintext> create_plaintext(){
            return std::make_shared<SEALPlaintext>(shared_from_this());
    }



    inline void decode(SEALPlaintext &plaintext, std::vector<double> &destination){
            encoder->decode(plaintext.plaintext(), destination);
    }

    inline void encode(std::vector<double> &values, double scale, SEALPlaintext& plaintext){
            encoder->encode(values, scale, plaintext.plaintext());
            plaintext.size() = values.size();
    }


    inline void encode(double value, double scale, SEALPlaintext& plaintext){
            encoder->encode(value, scale, plaintext.plaintext());
            plaintext.size() = 1;
    }

    inline void encrypt(SEALPlaintext &plaintext, SEALCiphertext& ciphertext){
        encryptor->encrypt(plaintext.plaintext(), ciphertext.ciphertext());
        ciphertext.size() = plaintext.size();
    }

    inline void decrypt(SEALCiphertext &ciphertext, SEALPlaintext &plaintext){
        //make sure no non-rescaled cophertexts going out.
        if(this->lazy_mode() && ciphertext.rescale_required){
            evaluator->rescale_to_next_inplace(ciphertext.ciphertext());
        }
        decryptor->decrypt(ciphertext.ciphertext(), plaintext.plaintext());
        plaintext.size() = ciphertext.size();
}


    inline size_t slot_count() const{
            return encoder->slot_count();
    }


private:
    bool m_simple_mode = false;
    bool m_lazy_mode = false;
    std::shared_ptr<SEALCtx> ctx;
    std::shared_ptr<seal::CKKSEncoder> encoder;
    std::shared_ptr<seal::Encryptor> encryptor;
    std::shared_ptr<seal::Decryptor> decryptor;
    std::shared_ptr<seal::Evaluator> evaluator;
}; // class SEALEngine

} // namespace hewrapper
