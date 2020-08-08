#include <iostream>
#include <cassert>
#include "SEALHE.h"

using namespace std;

namespace hewrapper{

    /*
     * check the scales, if not match, rescale.
     * check the modulus, if not match, match them.
     */

    inline bool _within_rescale_tolerance(double scale0, 
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
            assert(_within_rescale_tolerance(scale0, scale1));
            arg0.scale() = arg1.scale();
    }


    void _check_mod_and_scale(SEALCiphertext &arg0, 
                    SEALCiphertext &arg1, 
                    std::shared_ptr<hewrapper::SEALEngine> engine,
                    std::shared_ptr<seal::SEALContext> context
                    ){
        size_t chain_ind0 = context->get_context_data(arg0.ciphertext().parms_id())->chain_index();
        size_t chain_ind1 = context->get_context_data(arg1.ciphertext().parms_id())->chain_index();
        if (chain_ind0 == chain_ind1) {
            return;
        }
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
        _match_scale(arg0, arg1);
    }


    void _check_mod_and_scale(SEALCiphertext &arg0, 
                    SEALPlaintext &arg1,
                    std::shared_ptr<hewrapper::SEALEngine> engine,
                    std::shared_ptr<seal::SEALContext> context
                    ){

        size_t chain_ind0 = context->get_context_data(arg0.ciphertext().parms_id())->chain_index();
        size_t chain_ind1 = context->get_context_data(arg1.plaintext().parms_id())->chain_index();
        if (chain_ind0 == chain_ind1) {
            return;
        }
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
        _match_scale(arg0, arg1);
    }


    void seal_square_inplace(SEALCiphertext &arg0){
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        std::shared_ptr<seal::SEALContext> context = engine->get_context()->get_sealcontext();
        if(arg0.rescale_required){
            engine->get_evaluator()->rescale_to_next_inplace(arg0.ciphertext());
        }
        engine->get_evaluator()->square_inplace(arg0.ciphertext());
        engine->get_evaluator()->relinearize_inplace(arg0.ciphertext(), *(engine->get_context()->get_relin_keys()));
        if(engine->lazy_mode()){
            arg0.rescale_required = true;
        }else
        {
                engine->get_evaluator()->rescale_to_next_inplace(arg0.ciphertext());
        }
    }

    void seal_square(SEALCiphertext &arg0, SEALCiphertext &out){
            out = arg0;
            seal_square_inplace(out);
    }

    void _multiply_rescale(SEALCiphertext &arg0, 
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
    }

    void _multiply_rescale(SEALCiphertext &arg0, 
                    SEALPlaintext &arg1,
                    std::shared_ptr<hewrapper::SEALEngine> engine){
        if(arg0.rescale_required){
                engine->get_evaluator()->rescale_to_next_inplace(arg0.ciphertext());
                arg0.rescale_required = false;
        }
    }

    void seal_multiply_inplace(SEALCiphertext &arg0, SEALCiphertext &arg1){
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        std::shared_ptr<seal::SEALContext> context = engine->get_context()->get_sealcontext();
        if(engine->lazy_mode()){
                _multiply_rescale(arg0, arg1, engine);
        }
        _check_mod_and_scale(arg0, arg1, engine, context);
        engine->get_evaluator()->multiply_inplace(arg0.ciphertext(), arg1.ciphertext());
        engine->get_evaluator()->relinearize_inplace(arg0.ciphertext(), *(engine->get_context()->get_relin_keys()));
        if (engine->lazy_mode()){
                arg0.rescale_required = true;
        }else{
                engine->get_evaluator()->rescale_to_next_inplace(arg0.ciphertext());
        }
    }

    void seal_multiply_inplace(SEALCiphertext &arg0, SEALPlaintext &arg1){
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        std::shared_ptr<seal::SEALContext> context = engine->get_context()->get_sealcontext();
        if(engine->lazy_mode()){
                _multiply_rescale(arg0, arg1, engine);
        }
        _check_mod_and_scale(arg0, arg1, engine, context);
        engine->get_evaluator()->multiply_plain_inplace(arg0.ciphertext(), arg1.plaintext());
        if (engine->lazy_mode()){
                arg0.rescale_required = true;
        }else{
                engine->get_evaluator()->rescale_to_next_inplace(arg0.ciphertext());
        }
    }
    
    void seal_multiply(SEALCiphertext &arg0, SEALCiphertext &arg1, SEALCiphertext &out){
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        std::shared_ptr<seal::SEALContext> context = engine->get_context()->get_sealcontext();
        if(engine->lazy_mode()){
                _multiply_rescale(arg0, arg1, engine);
        }
        _check_mod_and_scale(arg0, arg1, engine, context);
        engine->get_evaluator()->relinearize_inplace(out.ciphertext(), *(engine->get_context()->get_relin_keys()));
        if (engine->lazy_mode()){
                out.rescale_required = true;
        }else{
                engine->get_evaluator()->rescale_to_next_inplace(out.ciphertext());
                out.rescale_required = false;
        }
    }

    void seal_multiply(SEALCiphertext &arg0, SEALPlaintext &arg1, SEALCiphertext &out){
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        std::shared_ptr<seal::SEALContext> context = engine->get_context()->get_sealcontext();
        if(engine->lazy_mode()){
                _multiply_rescale(arg0, arg1, engine);
        }
        _check_mod_and_scale(arg0, arg1, engine, context);
        engine->get_evaluator()->multiply_plain(arg0.ciphertext(), arg1.plaintext(), out.ciphertext());
        if (engine->lazy_mode()){
                out.rescale_required = true;
        }else{
                engine->get_evaluator()->rescale_to_next_inplace(out.ciphertext());
                out.rescale_required = false;
        }
    }

    void _add_rescale(SEALCiphertext &arg0, 
                    SEALCiphertext &arg1,
                    std::shared_ptr<hewrapper::SEALEngine> engine){
        if(arg0.rescale_required && arg1.rescale_required){
            return;
        }
        if(arg0.rescale_required){
                engine->get_evaluator()->rescale_to_next_inplace(arg0.ciphertext());
                arg0.rescale_required = false;
        }
        if(arg1.rescale_required){
                engine->get_evaluator()->rescale_to_next_inplace(arg1.ciphertext());
                arg1.rescale_required = false;
        }
    }

    void _add_rescale(SEALCiphertext &arg0, 
                    SEALPlaintext &arg1,
                    std::shared_ptr<hewrapper::SEALEngine> engine){
        if(arg0.rescale_required){
                engine->get_evaluator()->rescale_to_next_inplace(arg0.ciphertext());
                arg0.rescale_required = false;
        }
    }

    void seal_add_inplace(SEALCiphertext &arg0, SEALCiphertext &arg1){
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        std::shared_ptr<seal::SEALContext> context = engine->get_context()->get_sealcontext();
        if(engine->lazy_mode())_add_rescale(arg0, arg1, engine);
        _check_mod_and_scale(arg0, arg1, engine, context);
        engine->get_evaluator()->add_inplace(arg0.ciphertext(), arg1.ciphertext());
    }

    void seal_add_inplace(SEALCiphertext &arg0, SEALPlaintext &arg1){
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        std::shared_ptr<seal::SEALContext> context = engine->get_context()->get_sealcontext();
        if(engine->lazy_mode())_add_rescale(arg0, arg1, engine);
        _check_mod_and_scale(arg0, arg1, engine, context);
        engine->get_evaluator()->add_plain_inplace(arg0.ciphertext(), arg1.plaintext());
    }

    void seal_add(SEALCiphertext &arg0, SEALCiphertext &arg1, SEALCiphertext &out){
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        std::shared_ptr<seal::SEALContext> context = engine->get_context()->get_sealcontext();
        if(engine->lazy_mode())_add_rescale(arg0, arg1, engine);
        _check_mod_and_scale(arg0, arg1, engine, context);
        engine->get_evaluator()->add(arg0.ciphertext(), arg1.ciphertext(), out.ciphertext());
        out.rescale_required = arg0.rescale_required;
    }

    void seal_add(SEALCiphertext &arg0, SEALPlaintext &arg1, SEALCiphertext &out){
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        std::shared_ptr<seal::SEALContext> context = engine->get_context()->get_sealcontext();
        if(engine->lazy_mode())_add_rescale(arg0, arg1, engine);
        _check_mod_and_scale(arg0, arg1, engine, context);
        engine->get_evaluator()->add_plain(arg0.ciphertext(), arg1.plaintext(), out.ciphertext());
        out.rescale_required = arg0.rescale_required;
    }


}
    
