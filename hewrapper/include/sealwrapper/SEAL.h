#pragma once

#include <memory>
#include <vector>
#include <seal/seal.h>
#include "HEBase.h
// include here, so that users can only include this file
#include "SEALHE.h"
#include "SEALKey.h"
#include "SEALText.h"

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

class SEALEncryptionParameters : public EncryptionParametersBase {
public:
    friend class SEALCtx;

    EncryptionParametersBase() = delete;

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
        return public_key;
    }

    inline auto get_secret_key() {
        return secret_key;
    }

    inline auto get_relin_keys() {
        return relin_keys;
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

class SEALWrapper {
public:
    SEALWrapper(): ctx(NULL), encoder(NULL), encryptor(NULL), decryptor(NULL) {}

    void init(const SEALEncryptionParameters &parms);

    template<typename T, typename = std::enable_if_t<
            std::is_same<std::remove_cv_t<T>, double>::value ||
            std::is_same<std::remove_cv_t<T>, std::complex<double>>::value>>
    inline void encode(const std::vector<T> &values, double scale, SEALPlaintext &destination) {
        encoder->encode(values, scale, destination);
    }

    template<typename T, typename = std::enable_if_t<
            std::is_same<std::remove_cv_t<T>, double>::value ||
            std::is_same<std::remove_cv_t<T>, std::complex<double>>::value>>
    inline void encode(const std::vector<T> &values, double scale, SEALPlaintext &destination) {
        encoder->encode(values, scale, destination);
    }

    inline void encode(double value, double scale, SEALPlaintext &destination) {
        encoder->encode(value, scale, destination);
    }

    inline void encode(std::int64_t value, SEALPlaintext &destination) {
        encoder->encode(value, destination);
    }

    template<typename T, typename = std::enable_if_t<
            std::is_same<std::remove_cv_t<T>, double>::value ||
            std::is_same<std::remove_cv_t<T>, std::complex<double>>::value>>
    inline void decode(const SEALPlaintext &plain, std::vector<T> &destination) {
        encoder->decode(plain, destination);
    }

    inline std::size_t slot_count() const noexcept {
        return encode->slot_count();
    }

    inline std::shared_ptr<SEALEncryptor> get_encryptor() noexcept {
        return encryptor;
    }

    inline std::shared_ptr<SEALDecryptor> get_decryptor() noexcept {
        return decryptor;
    }

private:
    std::shared_ptr<SEALCtx> ctx;
    std::shared_ptr<SEALCKKSEncoder> encoder;
    std::shared_ptr<SEALEncryptor> encryptor;
    std::shared_ptr<SEALDecryptor> decryptor
};

} // namespace hewrapper