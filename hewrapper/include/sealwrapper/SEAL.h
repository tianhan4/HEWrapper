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

class SEALEncryptionParameters {
public:
    friend class SEALCtx;

    explicit SEALEncryptionParameters(seal_scheme sc = seal_scheme::none)
    : parms(static_cast<std::uint8_t>(sc)) {}

    inline void set_poly_modulus_degree(std::size_t poly_modulus_degree) {
        parms.set_poly_modulus_degree(poly_modulus_degree);
    }

    inline void set_coeff_modulus(std::size_t poly_modulus_degree, std::vector<int>& bit_sizes) {
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, bit_sizes));
    }

protected:
    EncryptionParameters parms;
}; // class SEALEncryptionParameters

class SEALCtx {
public:
    friend class SEALEncryptor;
    friend class SEALDecryptor;
    friend class SEALCKKSEncoder;

    static std::shared_ptr<SEALCtx> Create(const SEALEncryptionParameters &parms) {
        return std::shared_ptr<SEALCtx>(
            new SEALCtx(SEALContext::Create(parms.parms))
        );
    }

    inline auto get_public_key() {
        return *public_key;
    }

    inline auto get_secret_key() {
        return *secret_key;
    }

    inline auto get_relin_keys() {
        return *relin_keys;
    }

protected:
    std::shared_ptr<SEALContext> context;

private:
    SEALCtx(std::shared_ptr<SEALContext> ctx)
    :context(ctx),
     public_key(NULL),
     secret_key(NULL),
     relin_keys(NULL)
    {
        KeyGenerator keygen(context);
        public_key = std::make_shared<const PublicKey>(keygen.public_key());
        secret_key = std::make_shared<const SecretKey>(keygen.secret_key());
        relin_keys = std::make_shared<RelinKeys>(keygen.relin_keys());
    };

    SEALCtx(const SEALCtx &copy) = delete;

    SEALCtx(SEALCtx &&source) = delete;

    SEALCtx &operator =(const SEALCtx &assign) = delete;

    SEALCtx &operator =(SEALCtx &&assign) = delete;
    
    std::shared_ptr<const PublicKey> public_key;
    std::shared_ptr<const SecretKey> secret_key;
    std::shared_ptr<RelinKeys> relin_keys;
}; // class SEALCtx

} // namespace hewrapper