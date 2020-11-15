#pragma once

#include <memory>
#include <vector>
#include <seal/seal.h>

using namespace seal;

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

    SEALEncryptionParameters() = delete;

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
    static std::shared_ptr<SEALCtx> Create(const SEALEncryptionParameters &parms) {
        return std::shared_ptr<SEALCtx>(
            new SEALCtx(std::make_shared<SEALContext>(parms.parms))
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

private:
    SEALCtx(std::shared_ptr<SEALContext> ctx)
    :context(ctx)
    {
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
    
    std::shared_ptr<seal::SEALContext> context;
    std::shared_ptr<PublicKey> public_key;
    std::shared_ptr<SecretKey> secret_key;
    std::shared_ptr<RelinKeys> relin_keys;
    std::shared_ptr<GaloisKeys> galois_keys;
}; // class SEALCtx

} // namespace hewrapper
