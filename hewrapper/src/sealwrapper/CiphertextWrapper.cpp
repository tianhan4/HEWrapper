#include <seal/seal.h>
#include "CiphertextWrapper.h"

using namespace hewrapper;

    namespace hewrapper{
    void SEALCiphertext::load(std::istream &stream, std::shared_ptr<SEALEngine> engine){
        stream.read(reinterpret_cast<char *>(&this->rescale_required), sizeof(this->rescale_required));
        stream.read(reinterpret_cast<char *>(&this->relinearize_required), sizeof(this->relinearize_required));
        stream.read(reinterpret_cast<char *>(&this->m_size), sizeof(this->m_size));
        stream.read(reinterpret_cast<char *>(&this->m_clean), sizeof(this->m_clean));
        this->m_ciphertext.load(*(engine->get_context()->get_sealcontext()), stream);
    }

    std::streamoff SEALCiphertext::save(std::ostream &stream){
        stream.write(reinterpret_cast<const char *>(&this->rescale_required), sizeof(this->rescale_required));
        stream.write(reinterpret_cast<const char *>(&this->relinearize_required), sizeof(this->relinearize_required));
        stream.write(reinterpret_cast<const char *>(&this->m_size), sizeof(this->m_size));
        stream.write(reinterpret_cast<const char *>(&this->m_clean), sizeof(this->m_clean));
        auto ciphertext_offset = this->m_ciphertext.save(stream, seal::compr_mode_type::none);
        //cout << "ciphertext_offset:" << ciphertext_offset <<endl;
        return sizeof(this->rescale_required)  
        +sizeof(this->relinearize_required) 
        +sizeof(this->m_size)
        + sizeof(this->m_clean)
        + ciphertext_offset;
    }
}