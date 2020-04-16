#pragma once

#include <memory>
#include <vector>
#include <seal/seal.h>
#include "TextBase.h"
#include "sealwrapper/SEAL.h"

using namespace seal;

namespace hewrapper {

class SEALPlaintext : public PlainTextBase {
public:
    friend class SEALCKKSEncoder;
    friend class SEALCiphertext;

    SEALPlaintext() = default;

    inline auto scale() const noexcept {
        return plaintext.scale();
    }

    SEALPlaintext(const SEALPlaintext &copy) = default;
    SEALPlaintext(SEALPlaintext &&copy) = default;
    SEALPlaintext& operator=(const SEALPlaintext &assign) = default;
    SEALPlaintext& operator=(SEALPlaintext &&assign) = default;
    
protected:
    Plaintext plaintext;
}; // class SEALPlaintext

class SEALCKKSEncoder {
public:
    SEALCKKSEncoder(std::shared_ptr<SEALCtx> ctx): encoder(ctx->context) {};

    inline std::size_t slot_count() const noexcept {
        return encoder.slot_count();
    }

    template<typename T, typename = std::enable_if_t<
            std::is_same<std::remove_cv_t<T>, double>::value ||
            std::is_same<std::remove_cv_t<T>, std::complex<double>>::value>>
    inline void encode(const std::vector<T> &values, double scale, SEALPlaintext &destination) {
        encoder.encode(values, scale, destination.plaintext);
    }

    inline void encode(double value, double scale, SEALPlaintext &destination) {
        encoder.encode(value, scale, destination.plaintext);
    }

    inline void encode(std::int64_t value, SEALPlaintext &destination) {
        encoder.encode(value, destination.plaintext);
    }

    template<typename T, typename = std::enable_if_t<
            std::is_same<std::remove_cv_t<T>, double>::value ||
            std::is_same<std::remove_cv_t<T>, std::complex<double>>::value>>
    inline void decode(const SEALPlaintext &plain, std::vector<T> &destination) {
        encoder.decode(plain.plaintext, destination);
    }

private:
    CKKSEncoder encoder;
}; // class SEALCKKSEncoder

} // namespace hewrapper