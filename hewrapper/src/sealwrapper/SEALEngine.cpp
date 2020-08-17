#include <seal/seal.h>
#include "SEALEngine.h"
#include "SEALCtx.h"
#include "CiphertextWrapper.h"
#include "PlaintextWrapper.h"

using namespace hewrapper;

void SEALEngine::init(const SEALEncryptionParameters &parms, bool lazy_mode) {
    this->m_lazy_mode = lazy_mode;
    this->ctx = SEALCtx::Create(parms);
    this->encoder = std::make_shared<seal::CKKSEncoder>(ctx->get_sealcontext());
    this->encryptor = std::make_shared<seal::Encryptor>(ctx->get_sealcontext(),
                    *(ctx->get_public_key()));
    this->decryptor = std::make_shared<seal::Decryptor>(ctx->get_sealcontext(),
                    *(ctx->get_secret_key()));
    this->evaluator = std::make_shared<seal::Evaluator>(ctx->get_sealcontext());
}
