#pragma once
#include <memory>
#include <seal/seal.h>
#include "SEALEngine.h"
using namespace seal;

namespace hewrapper {
class SEALEngine;

class SEALPlaintext {
public:
    SEALPlaintext() = delete;

    SEALPlaintext(std::shared_ptr<SEALEngine> sealengine)
            :m_sealengine(sealengine){}

    SEALPlaintext(seal::Plaintext plaintext,
                    size_t size,
                    std::shared_ptr<SEALEngine> sealengine)
            :m_size(size), m_sealengine(sealengine), m_plaintext(plaintext){}

    inline auto size() const{
            return m_size;
    }
    inline auto &size(){
            return m_size;
    }

    //void save(pd::HEType& he_type) const;

    //static void load(SEALPlaintext& dst, const pb::HEType & he_type,
    //                std::shared_ptr<hewrapper::SEALEngine> sealengine);

    inline seal::Plaintext& plaintext(){
            return m_plaintext;
    }

    inline auto &scale(){
            return m_plaintext.scale();
    }

    inline auto scale() const{
            return m_plaintext.scale();
    }

    SEALPlaintext(const SEALPlaintext &copy) = default;
    SEALPlaintext(SEALPlaintext &&copy) = default;
    SEALPlaintext& operator=(const SEALPlaintext &assign) = default;
    SEALPlaintext& operator=(SEALPlaintext &&assign) = default;
private:
    size_t m_size;
    std::shared_ptr<hewrapper::SEALEngine> m_sealengine;
    seal::Plaintext m_plaintext;
};

} // namespace hewrapper
