#pragma once

#include <memory>
#include <vector>
#include <seal/seal.h>
#include <iostream>

using namespace seal;
using namespace std;

namespace hewrapper {

// Copy from seal `scheme_type`
enum class seal_scheme : std::uint8_t {
    // No scheme set; cannot be used for encryption
    none = 0x0,

    // Brakerski/Fan-Vercauteren scheme
    BFV = 0x1,

    // Cheon-Kim-Kim-Song scheme
    CKKS = 0x2
};

class SEALEncryptionParameters{
public:
    friend class SEALCtx;

    SEALEncryptionParameters(){};

    SEALEncryptionParameters(size_t poly_modulus_degree,
                    std::vector<int> bit_sizes,
                    seal_scheme sc = seal_scheme::none)
    : parms(static_cast<std::uint8_t>(sc)) {
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, bit_sizes));
    }

protected:
    EncryptionParameters parms; 
}; // class SEALEncryptionParameters

class SEALCtx {
public:

    SEALCtx(){};
    
    static std::shared_ptr<SEALCtx> Create(const SEALEncryptionParameters &parms) {
        return std::shared_ptr<SEALCtx>(
            new SEALCtx(parms)
        );  
    }

    inline const auto get_public_key() {
        return public_key;
    }

    inline const auto get_secret_key() {
        return secret_key;
    }

    inline const auto get_relin_keys() {
        return relin_keys;
    }
    inline const auto get_galois_keys() {
        return galois_keys;
    }

    inline std::shared_ptr<seal::SEALContext> get_sealcontext() const{
        return context;
    }


    
    inline std::streamoff save(std::ostream &stream, bool is_rotate, bool is_decrypt)
    {
        auto parm_save_size = this->m_parms.parms.save(stream);
        
        auto public_key_save_size = this->public_key->save(stream);
        
        auto relin_key_save_size = this->relin_keys->save(stream);
        std::streamoff galois_key_save_size = 0L;
        stream.write(reinterpret_cast<const char *>(&is_rotate), sizeof(is_rotate));
        if(is_rotate){
            galois_key_save_size = this->galois_keys->save(stream);
        }
        std::streamoff secret_key_save_size = 0L;
        stream.write(reinterpret_cast<const char *>(&is_decrypt), sizeof(is_decrypt));
        if(is_decrypt)
            secret_key_save_size = this->secret_key->save(stream);
        return parm_save_size
        + public_key_save_size 
        + relin_key_save_size
        + galois_key_save_size 
        + secret_key_save_size;
    }

    inline std::streamoff load(std::istream &stream){
        bool is_rotate, is_decrypt;
        secret_key = std::make_shared<SecretKey>();
        public_key = std::make_shared<PublicKey>();
        relin_keys = std::make_shared<RelinKeys>();
        galois_keys = std::make_shared<GaloisKeys>();
        auto parm_load_size = this->m_parms.parms.load(stream);
        this->context = std::make_shared<SEALContext>(m_parms.parms);
        auto public_key_load_size = this->public_key->load(*(this->context), stream);
        
        auto relin_key_load_size = this->relin_keys->load(*(this->context), stream);
        std::streamoff galois_key_load_size = 0L;
        std::streamoff secret_key_load_size = 0l;
        stream.read(reinterpret_cast<char *>(&is_rotate), sizeof(is_rotate));
        if(is_rotate){
            galois_key_load_size = this->galois_keys->load(*(this->context), stream);
        }
        else
        {
            this->galois_keys = NULL;
        }
        
        stream.read(reinterpret_cast<char *>(&is_decrypt), sizeof(is_decrypt));
        if(is_decrypt){
            secret_key_load_size = this->secret_key->load(*(this->context), stream);
        }
        else
        {
            this->secret_key = NULL;
        }
        return parm_load_size
        + public_key_load_size 
        + relin_key_load_size
        + galois_key_load_size 
        + secret_key_load_size;
    }

private:
    SEALCtx(SEALEncryptionParameters parms):m_parms(parms)
    {
        context = std::make_shared<SEALContext>(parms.parms);
        KeyGenerator keygen(*context);
        secret_key = std::make_shared<SecretKey>(keygen.secret_key());
        public_key = std::make_shared<PublicKey>();
        keygen.create_public_key(*public_key);
        relin_keys = std::make_shared<RelinKeys>();
        keygen.create_relin_keys(*relin_keys);
        galois_keys = std::make_shared<GaloisKeys>();
        keygen.create_galois_keys(*galois_keys);
    };

    SEALCtx(const SEALCtx &copy) = delete;

    SEALCtx(SEALCtx &&source) = delete;

    SEALCtx &operator =(const SEALCtx &assign) = delete;

    SEALCtx &operator =(SEALCtx &&assign) = delete;
    
    SEALEncryptionParameters m_parms;
    std::shared_ptr<seal::SEALContext> context;
    std::shared_ptr<PublicKey> public_key;
    std::shared_ptr<SecretKey> secret_key;
    std::shared_ptr<RelinKeys> relin_keys;
    std::shared_ptr<GaloisKeys> galois_keys;
}; // class SEALCtx

} // namespace hewrapper
