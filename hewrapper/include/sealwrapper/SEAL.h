#pragma once

// include here, so that users can only include this file
#include "SEALCtx.h"
#include "SEALKey.h"
#include "SEALText.h"
#include "SEALHE.h"

namespace hewrapper {

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
        return encoder->slot_count();
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
    std::shared_ptr<SEALDecryptor> decryptor;
}; // class SEALWrapper

} // namespace hewrapper