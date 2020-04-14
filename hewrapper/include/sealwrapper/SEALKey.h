#pragma once

#include <memory>
#include <seal/seal.h>
#include "KeyBase.h"

using namespace seal;

namespace hewrapper {

class SEALEncryptor : public PubKeyBase {
public:
    friend class SEALCtx;

    explicit SEALEncryptor(std::shared_ptr<SEALContext> ctx)
    : encryptor(ctx->context, ctx->get_public_key()),
      evaluator(ctx->context) {}

protected:
    Encryptor encryptor;
    std::shared_ptr<SEALEvaluator> evaluator;
}

class SEALDecryptor : public PrivateKeyBase {
public:
    friend class SEALCtx;

    explicit SEALDecryptor(std::shared_ptr<SEALContext> ctx)
    : decryptor(ctx->context, ctx->get_secret_key()) {}

protected:
    Decryptor decryptor;
}

} // namespace hewrapper