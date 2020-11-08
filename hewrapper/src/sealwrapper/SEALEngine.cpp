#include <seal/seal.h>
#include "SEALEngine.h"
#include "SEALCtx.h"
#include "CiphertextWrapper.h"
#include "PlaintextWrapper.h"

using namespace hewrapper;

void SEALEngine::init(const SEALEncryptionParameters &parms, size_t standard_scale, bool lazy_mode, bool auto_mod_switch, bool noise_mode) {
    this->m_standard_scale = pow(2.0, standard_scale);
    this->m_lazy_mode = lazy_mode;
    this->m_auto_mod_switch = auto_mod_switch;
    this->m_noise_mode = noise_mode;
    this->ctx = SEALCtx::Create(parms);
    this->encoder = std::make_shared<seal::CKKSEncoder>(ctx->get_sealcontext());
    this->encryptor = std::make_shared<seal::Encryptor>(ctx->get_sealcontext(),
                    *(ctx->get_public_key()));
    this->decryptor = std::make_shared<seal::Decryptor>(ctx->get_sealcontext(),
                    *(ctx->get_secret_key()));
    this->evaluator = std::make_shared<seal::Evaluator>(ctx->get_sealcontext());
    this->m_max_slot = this->encoder->slot_count();
}
