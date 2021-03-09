#include <seal/seal.h>
#include "SEALEngine.h"
#include "NetIO.h"


void seal_add(const SEALCiphertext &arg0, SEALPlaintext &arg1, SEALCiphertext &out);
using namespace hewrapper;

namespace hewrapper{
    void SEALEngine::init(const SEALEncryptionParameters &parms, size_t standard_scale, bool lazy_mode, bool auto_mod_switch, bool noise_mode) {
        this->m_standard_scale = pow(2.0, standard_scale);
        this->m_lazy_mode = lazy_mode;
        this->m_auto_mod_switch = auto_mod_switch;
        this->m_noise_mode = noise_mode;
        this->ctx = SEALCtx::Create(parms);
        this->encoder = std::make_shared<seal::CKKSEncoder>(*(ctx->get_sealcontext()));
        this->encryptor = std::make_shared<seal::Encryptor>(*(ctx->get_sealcontext()),
                        *(ctx->get_public_key()));
        this->decryptor = std::make_shared<seal::Decryptor>(*(ctx->get_sealcontext()),
                        *(ctx->get_secret_key()));
        this->evaluator = std::make_shared<seal::Evaluator>(*(ctx->get_sealcontext()));
        this->m_max_slot = this->encoder->slot_count();
    }

    void SEALEngine::createNetworkIO(const char * address, int port){
        this->network_io = make_shared<NetIO>(address, port, this->shared_from_this());
    }

    void SEALEngine::decode(SEALPlaintext &plaintext, std::vector<double> &destination){
        if(plaintext.clean()){
            destination.resize(plaintext.size());
            std::fill(destination.begin(), destination.end(), 0.0);
            return;
        }
        int vector_size = plaintext.size();
        encoder->decode(plaintext.plaintext(), destination);
        destination.resize(vector_size);
        //std::vector<double> sub(destination.cbegin(), destination.cbegin() + plaintext.size());
        //return sub;
    }

    void SEALEngine::encode(std::vector<double> &values, SEALPlaintext& plaintext){
        encode(values, this->m_standard_scale, plaintext);
        plaintext.init(shared_from_this());
    }

    void SEALEngine::encode(double value, SEALPlaintext& plaintext){
        encode(value, this->m_standard_scale, plaintext);
        plaintext.init(shared_from_this());
    }

    void SEALEngine::encode(std::vector<double> &values, double scale, SEALPlaintext& plaintext){
        int old_size = values.size();
        plaintext.size() = old_size;
        auto slot_count = encoder->slot_count();
        if (values.size() > slot_count)
                // number of slots available is poly_modulus_degree / 2
                throw std::invalid_argument(
                "can't encrypt vectors of this size, please use a larger "
                "polynomial modulus degree.");
        replicate_vector(values, slot_count);
        encoder->encode(values, scale, plaintext.plaintext());
        values.resize(old_size);
        plaintext.init(shared_from_this());
    }


    void SEALEngine::encode(double value, double scale, SEALPlaintext& plaintext){  
        encoder->encode(value, scale, plaintext.plaintext());
        plaintext.size() = 1;
        plaintext.init(shared_from_this());
        if (abs(value) < 1e-6){
            //cout << "scalar" << value << endl;
            plaintext.clean() = true;
        }
    }

    void SEALEngine::encrypt(SEALPlaintext &plaintext, SEALCiphertext& ciphertext){
        if (zero && (&ciphertext!=zero)){
            //cout << "zero!" << endl;
            seal_add(*zero, plaintext, ciphertext);
            ciphertext.clean() = false;
            ciphertext.size() = plaintext.size();
            ciphertext.init(shared_from_this());
            ciphertext.relinearize_required = false;
            ciphertext.rescale_required = false;
        }else{
            //cout <<" non zero!" << endl;
            encryptor->encrypt(plaintext.plaintext(), ciphertext.ciphertext());
            ciphertext.clean() = false;
            ciphertext.size() = plaintext.size();
            ciphertext.init(shared_from_this());
            ciphertext.relinearize_required = false;
            ciphertext.rescale_required = false;
        }
    }

    void SEALEngine::decrypt(SEALCiphertext &ciphertext, SEALPlaintext &plaintext){
        if(ciphertext.clean()){
            cout << "why decrypt a clean ciphertext?" << endl;
            plaintext.clean() = true;
            plaintext.size() = ciphertext.size();
            return;
        }
        //make sure no non-rescaled cophertexts going out.
        //why comment this?
        //Because we assume all decrypt plaintext will not be encrypted directly again.
        //if(this->lazy_mode() && ciphertext.rescale_required){
        //    evaluator->rescale_to_next_inplace(ciphertext.ciphertext());
        //}
        //if(this->lazy_mode() && ciphertext.relinearize_required){
        //    evaluator->relinearize_inplace(ciphertext.ciphertext(), *(ctx->get_relin_keys()));
        //}
        decryptor->decrypt(ciphertext.ciphertext(), plaintext.plaintext());
        plaintext.size() = ciphertext.size();
    }

    std::streamoff SEALEngine::save(std::ostream &stream, bool is_rotate, bool is_decrypt)
    {
        stream.write(reinterpret_cast<const char *>(&this->m_standard_scale), sizeof(this->m_standard_scale));
        stream.write(reinterpret_cast<const char *>(&this->m_lazy_mode), sizeof(this->m_lazy_mode));
        stream.write(reinterpret_cast<const char *>(&this->m_auto_mod_switch), sizeof(this->m_auto_mod_switch));
        stream.write(reinterpret_cast<const char *>(&this->m_noise_mode), sizeof(this->m_noise_mode));
        
        auto context_offset = this->ctx->save(stream, is_rotate, is_decrypt);
        
        stream.write(reinterpret_cast<const char *>(&this->m_max_slot), sizeof(this->m_max_slot));
        stream.write(reinterpret_cast<const char *>(&this->zero), sizeof(this->zero));
        /*cout << "save engine:" 
        << "context_offset" << context_offset
        << "together" << sizeof(this->m_standard_scale)  
        +sizeof(this->m_lazy_mode) 
        +sizeof(this->m_auto_mod_switch)
        + sizeof(this->m_noise_mode)
        + sizeof(this->zero)
        + context_offset
        + sizeof(this->m_max_slot) << endl;*/
        return sizeof(this->m_standard_scale)  
        +sizeof(this->m_lazy_mode) 
        +sizeof(this->m_auto_mod_switch)
        + sizeof(this->m_noise_mode)
        + context_offset
        + sizeof(this->zero)
        + sizeof(this->m_max_slot);
    }

    std::streamoff SEALEngine::load(std::istream &stream){
        stream.read(reinterpret_cast<char *>(&this->m_standard_scale), sizeof(this->m_standard_scale));
        stream.read(reinterpret_cast<char *>(&this->m_lazy_mode), sizeof(this->m_lazy_mode));
        stream.read(reinterpret_cast<char *>(&this->m_auto_mod_switch), sizeof(this->m_auto_mod_switch));
        stream.read(reinterpret_cast<char *>(&this->m_noise_mode), sizeof(this->m_noise_mode));

        this->ctx = std::make_shared<SEALCtx>();
        auto context_offset = this->ctx->load(stream);
        stream.read(reinterpret_cast<char *>(&this->m_max_slot), sizeof(this->m_max_slot));
        
        this->encoder = std::make_shared<seal::CKKSEncoder>(*(ctx->get_sealcontext()));
        this->encryptor = std::make_shared<seal::Encryptor>(*(ctx->get_sealcontext()),
                        *(ctx->get_public_key()));
        if(ctx->get_secret_key())
            this->decryptor = std::make_shared<seal::Decryptor>(*(ctx->get_sealcontext()), *(ctx->get_secret_key()));
        else
            this->decryptor = NULL;
        this->evaluator = std::make_shared<seal::Evaluator>(*(ctx->get_sealcontext()));
        
        stream.read(reinterpret_cast<char *>(&this->zero), sizeof(this->zero));
        if(this->zero){
            this->zero = new SEALCiphertext(shared_from_this());
            SEALPlaintext tmp;
            this->encode(0, tmp);
            this->encrypt(tmp, *(this->zero));
        }
        /*
        cout << "load engine:" 
        << "context_offset" << context_offset
        << "together" << sizeof(this->m_standard_scale)  
        +sizeof(this->m_lazy_mode) 
        +sizeof(this->m_auto_mod_switch)
        + sizeof(this->m_noise_mode)
        + sizeof(this->zero)
        + context_offset
        + sizeof(this->m_max_slot) << endl;*/

        return sizeof(this->m_standard_scale)  
        +sizeof(this->m_lazy_mode) 
        +sizeof(this->m_auto_mod_switch)
        + sizeof(this->m_noise_mode)
        + sizeof(this->zero)
        + context_offset
        + sizeof(this->m_max_slot);
    }
}
