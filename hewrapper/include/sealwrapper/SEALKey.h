#pragma once

#include <memory>
#include <seal/seal.h>
#include "KeyBase.h"
#include "sealwrapper/SEAL.h"

using namespace seal;

namespace hewrapper {

class SEALEncryptor : public PubKeyBase {
public:
    friend class SEALCiphertext;

    ~SEALEncryptor() = default;

    explicit SEALEncryptor(std::shared_ptr<SEALCtx> ctx)
    : encryptor(ctx->context, ctx->get_public_key()),
      evaluator(std::make_shared<Evaluator>(ctx->context)) {}

protected:
    Encryptor encryptor;
    std::shared_ptr<Evaluator> evaluator;

private:
    SEALEncryptor() = default;
};

class SEALDecryptor : public PrivateKeyBase {
public:
    friend class SEALCiphertext;

    ~SEALDecryptor() = default;

    explicit SEALDecryptor(std::shared_ptr<SEALCtx> ctx)
    : decryptor(ctx->context, ctx->get_secret_key()) {}

protected:
    Decryptor decryptor;

private:
    SEALDecryptor() = default;
};

} // namespace hewrapper