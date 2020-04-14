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
    SEALPlaintext() = default;

protected:
    Plaintext plaintext;
} // class SEALPlaintext

class SEALCKKSEncoder : public PlainTextBase {
public:
    friend class SEALCtx;
    friend class SEALPlaintext;

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

    template<typename T, typename = std::enable_if_t<
            std::is_same<std::remove_cv_t<T>, double>::value ||
            std::is_same<std::remove_cv_t<T>, std::complex<double>>::value>>
    inline void decode(const SEALPlaintext &plain, std::vector<T> &destination) {
        encoder.decode(plain.plaintext, destination);
    }

private:
    CKKSEncoder encoder;
} // class SEALCKKSEncoder

} // namespace hewrapper