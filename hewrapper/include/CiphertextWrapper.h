#pragma once
#include <memory>
#include <seal/seal.h>
#include "SEALEngine.h"

using namespace seal;

namespace hewrapper {
class SEALEngine;
class SEALCiphertext{
public:
    SEALCiphertext() = delete;

    SEALCiphertext( std::shared_ptr<SEALEngine> sealengine)
    :m_sealengine(sealengine){}

    SEALCiphertext(seal::Ciphertext ciphertext, 
                    size_t size,
                    std::shared_ptr<SEALEngine> sealengine)
    :m_size(size), m_sealengine(sealengine), m_ciphertext(ciphertext){}
    
    inline auto &size(){
            return m_size;
    }

    inline auto size() const{
            return m_size;
    }

    inline seal::Ciphertext& ciphertext(){
        return m_ciphertext;
    }
    // only permit on-site modification.
    inline auto &scale(){
        return m_ciphertext.scale();
    }
    inline auto scale() const{
            return m_ciphertext.scale();
    }

    //void save(pd::HEType& he_type) const;

    //static void load(SEALCiphertext& dst, const pb::HEType & he_type,
    //                std::shared_ptr<hewrapper::SEALEngine> sealengine);

    inline const std::shared_ptr<SEALEngine> getSEALEngine() const{
            return m_sealengine;
    }

    SEALCiphertext(const SEALCiphertext &copy) = default;
    SEALCiphertext(SEALCiphertext &&copy) = default;
    SEALCiphertext& operator=(const SEALCiphertext &assign) = default;
    SEALCiphertext& operator=(SEALCiphertext &&assign) = default;

    bool rescale_required = false;
private:
    size_t m_size;
    std::shared_ptr<SEALEngine> m_sealengine;
    Ciphertext m_ciphertext;
};

} // namespace hewrapper
