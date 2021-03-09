#include <iostream>
#include "SEALHE.h"
#include "SEALEngine.h"
#include "CiphertextWrapper.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/uintarith.h"

using namespace std;

namespace hewrapper{
    inline static void _multiply_rescale(SEALCiphertext &arg0, 
                    double arg1,
                    std::shared_ptr<hewrapper::SEALEngine> engine){
        if(arg0.rescale_required){
                engine->get_evaluator()->rescale_to_next_inplace(arg0.ciphertext());
                arg0.rescale_required = false;
        }
        if(arg0.relinearize_required){
            engine->get_evaluator()->relinearize_inplace(arg0.ciphertext(), *(engine->get_context()->get_relin_keys()));
            arg0.relinearize_required = false;
        }
    }

    inline static void _multiply_rescale(SEALCiphertext &arg0, 
                    SEALCiphertext &arg1,
                    std::shared_ptr<hewrapper::SEALEngine> engine){
        if(arg0.rescale_required){
                engine->get_evaluator()->rescale_to_next_inplace(arg0.ciphertext());
                arg0.rescale_required = false;
        }
        if(arg1.rescale_required){
                engine->get_evaluator()->rescale_to_next_inplace(arg1.ciphertext());
                arg0.rescale_required = false;
        }
        if(arg0.relinearize_required){
            engine->get_evaluator()->relinearize_inplace(arg0.ciphertext(), *(engine->get_context()->get_relin_keys()));
            arg0.relinearize_required = false;

        }
        if(arg1.relinearize_required){
            engine->get_evaluator()->relinearize_inplace(arg1.ciphertext(), *(engine->get_context()->get_relin_keys()));
            arg1.relinearize_required = false;
        }
    }

    inline static void _multiply_rescale(SEALCiphertext &arg0, 
                    SEALPlaintext &arg1,
                    std::shared_ptr<hewrapper::SEALEngine> engine){
        if(arg0.relinearize_required){
            engine->get_evaluator()->relinearize_inplace(arg0.ciphertext(), *(engine->get_context()->get_relin_keys()));
            arg0.relinearize_required = false;
        }
        if(arg0.rescale_required){
                engine->get_evaluator()->rescale_to_next_inplace(arg0.ciphertext());
                arg0.rescale_required = false;
        }
    }

    static void replicate_first_slot_inplace(SEALCiphertext &arg0, double coefficient = 1.0) {
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        std::shared_ptr<hewrapper::SEALCtx> hewrapperCtx = engine->get_context();
        int max_slot = engine->max_slot();
        // mask
        int slot_count = arg0.getSEALEngine()->slot_count();
        vector<double> mask(arg0.size(), 0);
        mask[0] = coefficient;
        SEALPlaintext plaintext(engine);
        engine->encode(mask, plaintext);
        seal_multiply_inplace(arg0, plaintext);
        if(arg0.relinearize_required){
            engine->get_evaluator()->relinearize_inplace(arg0.ciphertext(), *(engine->get_context()->get_relin_keys()));
            arg0.relinearize_required = false;
        }
        if(arg0.rescale_required){
                engine->get_evaluator()->rescale_to_next_inplace(arg0.ciphertext());
                arg0.rescale_required = false;
        }
        // replicate
        seal::Ciphertext tmp = arg0.ciphertext();
        auto &galois_keys = hewrapperCtx->get_galois_keys();
        for (size_t i = 0; i < (size_t)ceil(log2(max_slot)); i++) {
            engine->get_evaluator()->rotate_vector_inplace(
                    arg0.ciphertext(), static_cast<int>(-pow(2, i)), *galois_keys);
                engine->get_evaluator()->add_inplace(arg0.ciphertext(), tmp);
                tmp = arg0.ciphertext();
        }
        arg0.size() = 1;
    }


    /*
     * check the scales, if not match, rescale.
     * check the modulus, if not match, match them.
     */

    static inline bool _within_rescale_tolerance(double scale0, 
                    double scale1,
                    double factor = 1.05) {
                bool within_tolerance =
                                (scale0 / scale1 <= factor && scale1 / scale0 <= factor);
                return within_tolerance;
    }

    template <typename S, typename T>
    inline void _match_scale(S& arg0, const T& arg1){
            const auto scale0 = arg0.scale();
            const auto scale1 = arg1.scale();
            if (!_within_rescale_tolerance(scale0, scale1)){
                cout << scale0 << " " << scale1 << endl;
                throw std::invalid_argument(" Scaling factors mismatch!");
            }
            arg0.scale() = arg1.scale();
    }


    static void _check_mod_and_scale_and_size(SEALCiphertext &arg0, 
                    SEALCiphertext &arg1, 
                    std::shared_ptr<hewrapper::SEALEngine> engine,
                    std::shared_ptr<seal::SEALContext> context
                    ){
        size_t chain_ind0 = context->get_context_data(arg0.ciphertext().parms_id())->chain_index();
        size_t chain_ind1 = context->get_context_data(arg1.ciphertext().parms_id())->chain_index();
        if (!(chain_ind0 == chain_ind1) && engine->auto_mod_switch()) {
            //printf("Warning: mod adjustment happens, some improvements required.\n");
            //cout << "arg0 level: " << chain_ind0 << ", arg1 level: " << chain_ind1 << endl;
            //assert(false);
            if (chain_ind0 < chain_ind1) {
                auto arg0_parms_id = arg0.ciphertext().parms_id();
                engine->get_evaluator()->mod_switch_to_inplace(arg1.ciphertext(), arg0_parms_id);
                chain_ind1 = context->get_context_data(arg1.ciphertext().parms_id())->chain_index();
            } else {  // chain_ind0 > chain_ind1
                auto arg1_parms_id = arg1.ciphertext().parms_id();
                engine->get_evaluator()->mod_switch_to_inplace(arg0.ciphertext(), arg1_parms_id);
                chain_ind0 = context->get_context_data(arg0.ciphertext().parms_id())->chain_index();
            }
            assert(chain_ind0 == chain_ind1);
        }
        _match_scale(arg0, arg1);
        //match sizes
        if (arg0.size() != arg1.size()) {
            if (arg0.size() == 1) {
                //replicate_first_slot_inplace(arg0, arg1.size());
            } else if (arg1.size() == 1) {
                //replicate_first_slot_inplace(arg1, arg0.size());
            } else {
                cout << arg0.size() << " " << arg1.size() << endl;
                throw invalid_argument("can't add vectors of different sizes");
            }
        }

    }


    void _check_mod_and_scale_and_size(SEALCiphertext &arg0, 
                    SEALPlaintext &arg1,
                    std::shared_ptr<hewrapper::SEALEngine> engine,
                    std::shared_ptr<seal::SEALContext> context
                    ){

        size_t chain_ind0 = context->get_context_data(arg0.ciphertext().parms_id())->chain_index();
        size_t chain_ind1 = context->get_context_data(arg1.plaintext().parms_id())->chain_index();
        if (!(chain_ind0 == chain_ind1) && engine->auto_mod_switch()) {
            //printf("Warning: mod adjustment happens, some improvements required.\n");
            //cout << "arg0 level: " << chain_ind0 << ", arg1 level: " << chain_ind1 << endl;
            //assert(false);
            if (chain_ind0 < chain_ind1) {
                auto arg0_parms_id = arg0.ciphertext().parms_id();
                engine->get_evaluator()->mod_switch_to_inplace(arg1.plaintext(), arg0_parms_id);
                chain_ind1 = context->get_context_data(arg1.plaintext().parms_id())->chain_index();
            } else {  // chain_ind0 > chain_ind1
                auto arg1_parms_id = arg1.plaintext().parms_id();
                engine->get_evaluator()->mod_switch_to_inplace(arg0.ciphertext(), arg1_parms_id);
                chain_ind0 = context->get_context_data(arg0.ciphertext().parms_id())->chain_index();
            }
            assert(chain_ind0 == chain_ind1);
        }
        _match_scale(arg0, arg1);
        //match sizes
        //if (arg1.size() == 1)
            //printf("Warning: no plaintext with size 1, please just use scalar encoding.");
        if (arg0.size() != arg1.size()) {
            if (arg0.size() == 1 ||arg1.size() == 1  ) {
                //replicate_first_slot_inplace(arg0, arg1.size());
            }else {
                cout << arg0.size() << " " << arg1.size() << endl;
                throw invalid_argument("can't add vectors of different sizes");
            }
        }
    }

    void seal_square_inplace(SEALCiphertext &arg0, bool is_parameter){
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        std::shared_ptr<seal::SEALContext> context = engine->get_context()->get_sealcontext();
        if(!is_parameter && !engine->lazy_relinearization()) is_parameter = true;
        if(arg0.clean()){
            return;
        }
        if(arg0.relinearize_required){
            engine->get_evaluator()->relinearize_inplace(arg0.ciphertext(), *(engine->get_context()->get_relin_keys()));
            arg0.relinearize_required = false;
        }
        if(arg0.rescale_required){
            engine->get_evaluator()->rescale_to_next_inplace(arg0.ciphertext());
            arg0.rescale_required = false;
        }
        engine->get_evaluator()->square_inplace(arg0.ciphertext());
        if(is_parameter){
            engine->get_evaluator()->relinearize_inplace(arg0.ciphertext(), *(engine->get_context()->get_relin_keys()));
            arg0.relinearize_required = false;
            if (engine->lazy_mode()){
                arg0.rescale_required = true;
            }else{
                engine->get_evaluator()->rescale_to_next_inplace(arg0.ciphertext());
                arg0.rescale_required = false;
            }
        }else{
            if (engine->lazy_mode()){
                    arg0.rescale_required = true;
                    arg0.relinearize_required = true;
            }else{
                engine->get_evaluator()->relinearize_inplace(arg0.ciphertext(), *(engine->get_context()->get_relin_keys()));
                engine->get_evaluator()->rescale_to_next_inplace(arg0.ciphertext());
                arg0.rescale_required = false;
                arg0.relinearize_required = false;
            }
        }
    }

    //this should be faster.
    void seal_square(SEALCiphertext &arg0, SEALCiphertext &out, bool is_parameter){
            out = arg0;
            seal_multiply_inplace(out, arg0, is_parameter);
    }


    // is_parameter: immediately relinearize.
    void seal_multiply_inplace(SEALCiphertext &arg0, SEALCiphertext &arg1, bool is_parameter){
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        std::shared_ptr<seal::SEALContext> context = engine->get_context()->get_sealcontext();
        if(!is_parameter && !engine->lazy_relinearization()) is_parameter = true;
        if (arg0.clean() || arg1.clean()){
            arg0.clean() = true;
            return;
        }
        _multiply_rescale(arg0, arg1, engine);
        _check_mod_and_scale_and_size(arg0, arg1, engine, context);
        engine->get_evaluator()->multiply_inplace(arg0.ciphertext(), arg1.ciphertext());
        if(is_parameter){
            engine->get_evaluator()->relinearize_inplace(arg0.ciphertext(), *(engine->get_context()->get_relin_keys()));
            arg0.relinearize_required = false;
            if (engine->lazy_mode()){
                arg0.rescale_required = true;
            }else{
                engine->get_evaluator()->rescale_to_next_inplace(arg0.ciphertext());
                arg0.rescale_required = false;
            }
        }else{
            if (engine->lazy_mode()){
                    arg0.rescale_required = true;
                    arg0.relinearize_required = true;
            }else{
                engine->get_evaluator()->relinearize_inplace(arg0.ciphertext(), *(engine->get_context()->get_relin_keys()));
                engine->get_evaluator()->rescale_to_next_inplace(arg0.ciphertext());
                arg0.rescale_required = false;
                arg0.relinearize_required = false;
            }
        }
        arg0.size() = arg0.size()==1? arg1.size() : arg0.size();
        
    }

    void seal_multiply_inplace(SEALCiphertext &arg0, SEALPlaintext &arg1){
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        std::shared_ptr<seal::SEALContext> context = engine->get_context()->get_sealcontext();
        if (arg1.clean()){
            arg0.clean() = true;
            return;
        }
        if (arg0.clean()){
            return;
        }
        _multiply_rescale(arg0, arg1, engine);
        _check_mod_and_scale_and_size(arg0, arg1, engine, context);
        engine->get_evaluator()->multiply_plain_inplace(arg0.ciphertext(), arg1.plaintext());
        if (engine->lazy_mode()){
                arg0.rescale_required = true;
        }else{
                engine->get_evaluator()->rescale_to_next_inplace(arg0.ciphertext());
                arg0.rescale_required = false;
        }
        arg0.size() = arg0.size()==1? arg1.size() : arg0.size();
    }

    void seal_multiply(const SEALCiphertext &arg0, SEALCiphertext &arg1, SEALCiphertext &out, bool is_parameter){
        out = arg0;
        seal_multiply_inplace(out, arg1, is_parameter);

        /**
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        std::shared_ptr<seal::SEALContext> context = engine->get_context()->get_sealcontext();

        out = arg0;
        seal_multiply_inplace(out, arg1);


        if(!is_parameter && !engine->lazy_relinearization()) is_parameter = true;
        if (arg0.clean() || arg1.clean()){
            out.clean() = true;
            return;
        }else{
            out.clean() = false;
        }
                _multiply_rescale(arg0, arg1, engine);

        _check_mod_and_scale_and_size(arg0, arg1, engine, context);
        engine->get_evaluator()->multiply(arg0.ciphertext(), arg1.ciphertext(), out.ciphertext());
        if(is_parameter){
            engine->get_evaluator()->relinearize_inplace(out.ciphertext(), *(engine->get_context()->get_relin_keys()));
            out.relinearize_required = false;
            if (engine->lazy_mode()){
                out.rescale_required = true;
            }else{
               engine->get_evaluator()->rescale_to_next_inplace(out.ciphertext());
                out.rescale_required = false;
            }
        }else{
            if (engine->lazy_mode()){
                out.rescale_required = true;
                out.relinearize_required = true;
            }else{
                engine->get_evaluator()->relinearize_inplace(out.ciphertext(), *(engine->get_context()->get_relin_keys()));
                engine->get_evaluator()->rescale_to_next_inplace(out.ciphertext());
                out.rescale_required = false;
                out.relinearize_required = false;
            }
        }
        out.size() = arg0.size()==1? arg1.size(): arg0.size();
        **/
    }

    void seal_multiply(const SEALCiphertext &arg0, SEALPlaintext &arg1, SEALCiphertext &out){
        out = arg0;
        seal_multiply_inplace(out, arg1);
        /**
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        std::shared_ptr<seal::SEALContext> context = engine->get_context()->get_sealcontext();
        if (arg0.clean()){
            out.clean() = true;
            return;
        }else{
            out.clean() = false;
        }
                _multiply_rescale(arg0, arg1, engine);
        
        _check_mod_and_scale_and_size(arg0, arg1, engine, context);
        engine->get_evaluator()->multiply_plain(arg0.ciphertext(), arg1.plaintext(), out.ciphertext());
        if (engine->lazy_mode()){
                out.rescale_required = true;
        }else{
                engine->get_evaluator()->rescale_to_next_inplace(out.ciphertext());
                out.rescale_required = false;
        }
        out.size() = arg0.size()==1? arg1.size(): arg0.size();
        **/
    }


    void seal_multiply(const SEALCiphertext & arg0, double scalar, SEALCiphertext &out, const seal::MemoryPoolHandle& pool){
        //std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        //if(engine->simple_mode()){
        //    multiply_plain_simple_mod(arg0, scalar, out, engine, std::move(pool));
        //    cout << "finish mul" <<endl;
        //}else{
        out = arg0;
        seal_multiply_inplace(out, scalar, std::move(pool));
        //}
    }

    void seal_multiply_inplace(SEALCiphertext &arg0, double scalar, const seal::MemoryPoolHandle& pool){
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        std::shared_ptr<seal::SEALContext> context = engine->get_context()->get_sealcontext();
        if (arg0.clean()){
            return;
        }
        if(abs(scalar - 1.0)<1e-6){
            return;
        }
        if (abs(scalar) < 1e-6){
            cout << "scalar" << scalar << endl;
            arg0.clean() = true;
            return;
        }
        SEALPlaintext plaintext;
        engine->encode(scalar, engine->scale(), plaintext);
        seal_multiply_inplace(arg0, plaintext);
    }


    static void inverse_rescale(SEALCiphertext &arg0,
                    std::shared_ptr<hewrapper::SEALEngine> engine){
        std::shared_ptr<seal::SEALContext> context = engine->get_context()->get_sealcontext();
        if (arg0.clean()){
            return;
        }
        
        SEALPlaintext plaintext;
        //work around the 1.0 optimization in seal_multiply_inplace.
        engine->encode(1.0, engine->scale(), plaintext);
        seal_multiply_inplace(arg0, plaintext);
    }

    inline void _add_rescale(SEALCiphertext &arg0, 
                    SEALCiphertext &arg1,
                    std::shared_ptr<hewrapper::SEALEngine> engine){
        if(arg0.rescale_required && arg1.rescale_required){
        }
        else if(arg0.rescale_required){
                //engine->get_evaluator()->rescale_to_next_inplace(arg0.ciphertext());
                //arg0.rescale_required = false;
                inverse_rescale(arg1, engine);
                arg1.rescale_required = true;
        }
        else if(arg1.rescale_required){                
                //engine->get_evaluator()->rescale_to_next_inplace(arg1.ciphertext());
                //arg1.rescale_required = false;
                inverse_rescale(arg0, engine);
                arg0.rescale_required = true;
        }
        if(arg0.relinearize_required && arg1.relinearize_required){
        }else if (arg0.relinearize_required){
            engine->get_evaluator()->relinearize_inplace(arg0.ciphertext(), *(engine->get_context()->get_relin_keys()));
            arg0.relinearize_required = false;
        }else if(arg1.relinearize_required){
            engine->get_evaluator()->relinearize_inplace(arg1.ciphertext(), *(engine->get_context()->get_relin_keys()));
            arg1.relinearize_required = false;
        }

                        /**
        if(arg0.rescale_required && arg1.rescale_required){
        }
        else if(arg0.rescale_required){
                engine->get_evaluator()->rescale_to_next_inplace(arg0.ciphertext());
                arg0.rescale_required = false;
        }
        else if(arg1.rescale_required){
                engine->get_evaluator()->rescale_to_next_inplace(arg1.ciphertext());
                arg1.rescale_required = false;
        }
        if(arg0.relinearize_required && arg1.relinearize_required){
        }else if (arg0.relinearize_required){
            engine->get_evaluator()->relinearize_inplace(arg0.ciphertext(), *(engine->get_context()->get_relin_keys()));
            arg0.relinearize_required = false;
        }else if(arg1.relinearize_required){
            engine->get_evaluator()->relinearize_inplace(arg1.ciphertext(), *(engine->get_context()->get_relin_keys()));
            arg1.relinearize_required = false;
        }**/
    }

    inline void _add_rescale(SEALCiphertext &arg0, 
                    SEALPlaintext &arg1,
                    std::shared_ptr<hewrapper::SEALEngine> engine){
        if(arg0.relinearize_required){
            engine->get_evaluator()->relinearize_inplace(arg0.ciphertext(), *(engine->get_context()->get_relin_keys()));
            arg0.relinearize_required = false;
        }
        if(arg0.rescale_required){
                engine->get_evaluator()->rescale_to_next_inplace(arg0.ciphertext());
                arg0.rescale_required = false;
        }
    }

    void seal_add_inplace(SEALCiphertext &arg0, SEALCiphertext &arg1){
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        std::shared_ptr<seal::SEALContext> context = engine->get_context()->get_sealcontext();
        if (arg1.clean()){
            return;
        } 
        else if (arg0.clean()){
            arg0 = arg1;
            arg0.clean() = false;
            return;
        }
        _add_rescale(arg0, arg1, engine);
        _check_mod_and_scale_and_size(arg0, arg1, engine, context);
        engine->get_evaluator()->add_inplace(arg0.ciphertext(), arg1.ciphertext());
        arg0.size() = arg0.size()==1? arg1.size() : arg0.size();
    }

    void seal_add_inplace(SEALCiphertext &arg0, SEALPlaintext &arg1){
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        std::shared_ptr<seal::SEALContext> context = engine->get_context()->get_sealcontext();
        if (arg0.clean()){
            //printf("some bad operation: seal_add_inplace better not use clean ciphertexts as arg0 when adding plaintext.\n");
            //saved by zero encryption
            //cout << "oldsize:" << arg0.size() << endl;
            int old_size = arg0.size();
            engine->encrypt(arg1, arg0);
            if (old_size != 0){
                arg0.size() = old_size;   
            }
            //arg0.clean() = false;//no need
            return;
        }
        _add_rescale(arg0, arg1, engine);
        _check_mod_and_scale_and_size(arg0, arg1, engine, context);
        engine->get_evaluator()->add_plain_inplace(arg0.ciphertext(), arg1.plaintext());
        arg0.size() = arg0.size()==1? arg1.size() : arg0.size();
    }

    void seal_add(const SEALCiphertext &arg0, SEALCiphertext &arg1, SEALCiphertext &out){
        out = arg0;
        seal_add_inplace(out, arg1);
        /**
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        std::shared_ptr<seal::SEALContext> context = engine->get_context()->get_sealcontext();
        if (arg0.clean() && arg1.clean()) {
            out.clean() = true;
            return;
        }
        else if (!arg0.clean() && arg1.clean()){
            out = arg0;
            out.clean() = false;
            return;
        }
        else if (arg0.clean() && !arg1.clean()){
            out = arg1;
            out.clean() = false;
            return;
        }else 
            out.clean() = false;
        _add_rescale(arg0, arg1, engine);
        _check_mod_and_scale_and_size(arg0, arg1, engine, context);
        engine->get_evaluator()->add(arg0.ciphertext(), arg1.ciphertext(), out.ciphertext());
        out.rescale_required = arg0.rescale_required;
        out.size() = arg0.size()==1? arg1.size(): arg0.size();
        **/
    }

    void seal_add(const SEALCiphertext &arg0, SEALPlaintext &arg1, SEALCiphertext &out){
        out = arg0;
        seal_add_inplace(out, arg1);
        /**
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        std::shared_ptr<seal::SEALContext> context = engine->get_context()->get_sealcontext();
        if (arg0.clean()){
            printf("some bad operation: clean ciphertext with plaintext/scalar.\n");
            engine->encrypt(arg1, out);
            return;
        }
        _add_rescale(arg0, arg1, engine);
        _check_mod_and_scale_and_size(arg0, arg1, engine, context);
        engine->get_evaluator()->add_plain(arg0.ciphertext(), arg1.plaintext(), out.ciphertext());
        out.rescale_required = arg0.rescale_required;
        out.size() = arg0.size()==1? arg1.size(): arg0.size();
        **/
    }

    void seal_add(const SEALCiphertext &arg0, double scalar, SEALCiphertext &out){
        out = arg0;
        seal_add_inplace(out, scalar);
    }

    void seal_add_inplace(SEALCiphertext &arg0, double scalar){
        if(scalar == 0)return;
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        SEALPlaintext plaintext;
        engine->encode(scalar, plaintext);
        seal_add_inplace(arg0, plaintext);
    }

//copy from add, transform to sub.

    void seal_sub_inplace(SEALCiphertext &arg0, SEALCiphertext &arg1){
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        std::shared_ptr<seal::SEALContext> context = engine->get_context()->get_sealcontext();
        if (arg1.clean()){
            return;
        }
        if (arg0.clean()){
            engine->get_evaluator()->negate(arg1.ciphertext(), arg0.ciphertext());
            arg0.clean() = false;
            return;
        }
        _add_rescale(arg0, arg1, engine);
        _check_mod_and_scale_and_size(arg0, arg1, engine, context);
        engine->get_evaluator()->sub_inplace(arg0.ciphertext(), arg1.ciphertext());
        arg0.size() = arg0.size()==1? arg1.size() : arg0.size();
    }

    void seal_sub_inplace(SEALCiphertext &arg0, SEALPlaintext &arg1){
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        std::shared_ptr<seal::SEALContext> context = engine->get_context()->get_sealcontext();
        if (arg0.clean()){
            printf("some bad operation: clean ciphertext with plaintext/scalar.\n");
            engine->encrypt(arg1, arg0);
            engine->get_evaluator()->negate_inplace(arg0.ciphertext());
            return;
        }
        _add_rescale(arg0, arg1, engine);
        _check_mod_and_scale_and_size(arg0, arg1, engine, context);
        engine->get_evaluator()->sub_plain_inplace(arg0.ciphertext(), arg1.plaintext());
        arg0.size() = arg0.size()==1? arg1.size() : arg0.size();
    }

    void seal_sub(const SEALCiphertext &arg0, SEALCiphertext &arg1, SEALCiphertext &out){
        out = arg0;
        seal_sub_inplace(out, arg1);
        /**
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        std::shared_ptr<seal::SEALContext> context = engine->get_context()->get_sealcontext();
        if (arg1.clean()){
            out = arg0;
            out.clean() = false;
            return;
        }
        if (arg0.clean()){
            out = arg1;
            engine->get_evaluator()->negate_inplace(out.ciphertext());
            out.clean() = false;
            return;
        }
        _add_rescale(arg0, arg1, engine);
        _check_mod_and_scale_and_size(arg0, arg1, engine, context);
        engine->get_evaluator()->sub(arg0.ciphertext(), arg1.ciphertext(), out.ciphertext());
        out.rescale_required = arg0.rescale_required;
        out.size() = arg0.size()==1? arg1.size(): arg0.size();
        out.clean() = false;**/
    }

    void seal_sub(const SEALCiphertext &arg0, SEALPlaintext &arg1, SEALCiphertext &out){
        out = arg0;
        seal_sub_inplace(out, arg1);
        /**
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        std::shared_ptr<seal::SEALContext> context = engine->get_context()->get_sealcontext();
        if (arg0.clean()){
            printf("some bad operation: clean ciphertext with plaintext/scalar.\n");
            engine->encrypt(arg1, out);
            engine->get_evaluator()->negate_inplace(out.ciphertext());
            return;
        }
        _add_rescale(arg0, arg1, engine);
        _check_mod_and_scale_and_size(arg0, arg1, engine, context);
        engine->get_evaluator()->sub_plain(arg0.ciphertext(), arg1.plaintext(), out.ciphertext());
        out.rescale_required = arg0.rescale_required;
        out.size() = arg0.size()==1? arg1.size(): arg0.size();
        out.clean() = false;**/
    }

    void seal_sub(const SEALCiphertext &arg0, double scalar, SEALCiphertext &out){
        out = arg0;
        seal_sub_inplace(out, scalar);
    }

    void seal_sub_inplace(SEALCiphertext &arg0, double scalar){
        scalar = - scalar;
        if(scalar == 0)return;
        seal_add_inplace(arg0, scalar);
    }




    static size_t below_power2(size_t n) {
        if (n == 0) throw invalid_argument("n must be absolutely positive.");
        if (n && !(n & (n - 1))) return n;

        size_t count = 0;
        while (n != 1) {
            n >>= 1;
            count += 1;
        }
        return 1 << count;
    }


    static void sum_vector(SEALCiphertext &arg0, size_t size) {
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        std::shared_ptr<hewrapper::SEALCtx> hewrapperCtx = engine->get_context();
        if(arg0.clean()){
            throw invalid_argument("cannot sum a clean ciphertext.");
        }
        assert(size <= engine->get_encoder()->slot_count());
        // Nothing to do
        if (size == 1) return;

        auto galois_keys = hewrapperCtx->get_galois_keys();
        SEALCiphertext rest(engine), tmp(engine);
        size_t bp2 = below_power2(size);

        if (bp2 != size) {
            engine->get_evaluator()->rotate_vector(arg0.ciphertext(), bp2, *galois_keys,
                                                    rest.ciphertext());
            sum_vector(rest, size - bp2);
        }

        for (size_t i = bp2 / 2; i > 0; i /= 2) {
            engine->get_evaluator()->rotate_vector(arg0.ciphertext(), i, *galois_keys, tmp.ciphertext());
            engine->get_evaluator()->add_inplace(arg0.ciphertext(), tmp.ciphertext());
            tmp.ciphertext() = arg0.ciphertext();
        }

        if (bp2 != size) {
            engine->get_evaluator()->add_inplace(arg0.ciphertext(), rest.ciphertext());
        }
    }

    void sum_vector(SEALCiphertext &arg0, double coefficient) {
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        if(arg0.relinearize_required){
            engine->get_evaluator()->relinearize_inplace(arg0.ciphertext(), *(engine->get_context()->get_relin_keys()));
            arg0.relinearize_required = false;
        }
        if(arg0.rescale_required){
                engine->get_evaluator()->rescale_to_next_inplace(arg0.ciphertext());
                arg0.rescale_required = false;
        }
        sum_vector(arg0, arg0.size());
        replicate_first_slot_inplace(arg0, coefficient);
    }


/*
    SEALCiphertext & SEALCiphertext::operator+=(const SEALCiphertext &b){
        seal_add_inplace(*this, b);
        return *this;
    }

    SEALCiphertext & SEALCiphertext::operator+=(const SEALPlaintext &b){

        seal_add_inplace(*this, b);
        return *this;
    }
    SEALCiphertext & SEALCiphertext::operator+=(double b){

        seal_add_inplace(*this, b);
        return *this;
    }
    SEALCiphertext & SEALCiphertext::operator*=(const SEALCiphertext &b){
        seal_multiply_inplace(*this, b);
        return *this;
    }
    SEALCiphertext & SEALCiphertext::operator*=(const SEALPlaintext &b){

        seal_multiply_inplace(*this, b);
        return *this;
    }
    SEALCiphertext & SEALCiphertext::operator*=(double b){

        seal_multiply_inplace(*this, b);
        return *this;
    }
    */
}
    
