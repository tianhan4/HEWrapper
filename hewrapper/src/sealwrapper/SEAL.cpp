#include "sealwrapper/SEAL.h"

using namespace hewrapper;

void SEALWrapper::init(const SEALEncryptionParameters &parms) {
    ctx = SEALCtx::Create(parms);
    encoder = std::make_shared<SEALCKKSEncoder>(ctx);
    encryptor = std::make_shared<SEALCKKSEncoder>(ctx);
    decryptor = std::make_shared<SEALCKKSDecoder>(ctx);
}