#include <iostream>
#include "SEALHE.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/uintarith.h"

using namespace std;

namespace hewrapper{



void multiply_poly_scalar_coeffmod64(const uint64_t*poly,
            size_t coeff_count,
            uint64_t scalar,
            const seal::SmallModulus& modulus,
            std::uint64_t* result){
        const uint64_t modulus_value = modulus.value();
        const uint64_t const_ratio_l = modulus.const_ratio()[1];
        for (; coeff_count--; poly++, result++){
            auto z = *poly * scalar;
            unsigned long long carry;
            seal::util::multiply_uint64_hw64(z, const_ratio_l, &carry);
            carry = z - carry * modulus_value;
            *result = carry - (modulus_value & static_cast<uint64_t>(-static_cast<int64_t>(carry >= modulus_value)));
        }
    }


    void encode(double value, double scale, seal::parms_id_type parms_id,
            std::vector<std::uint64_t>& dest,
            const std::shared_ptr<hewrapper::SEALEngine> engine,
            const seal::MemoryPoolHandle & pool = seal::MemoryManager::GetPool()){
            std::shared_ptr<seal::SEALContext> context = engine->get_context()->get_sealcontext();
            auto& context_data = *context->get_context_data(parms_id);
            auto& parms = context_data.parms();
            auto& coeff_modulus = parms.coeff_modulus();
            //size_t coeff_count = parms.poly_modulus_degree();
            size_t coeff_mod_count = coeff_modulus.size();
            value *= scale;

            int coeff_bit_count = static_cast<int>(log2(fabs(value))) + 2;
            if (coeff_bit_count >= context_data.total_coeff_modulus_bit_count()){
                throw "encoded value is too large";
    }
            double two_pow_64 = pow(2.0, 64);
            dest.resize(coeff_mod_count);
            double coeffd = std::round(value);
            bool is_negative = std::signbit(coeffd);
            coeffd = fabs(coeffd);

            if (coeff_bit_count <= 64){
                auto coeffu = static_cast<uint64_t>(fabs(coeffd));
                if (is_negative){
                    for (size_t j=0; j< coeff_mod_count; j++){
                        dest[j] = seal::util::negate_uint_mod(coeffu % coeff_modulus[j].value(), coeff_modulus[j]);
                    }
                }
                else{
                    for (size_t j = 0; j < coeff_mod_count; j++) {
                        dest[j] = coeffu % coeff_modulus[j].value();
                    }
                }
            }
            else if (coeff_bit_count <= 128){
                uint64_t coeffu[2]{static_cast<uint64_t>(fmod(coeffd, two_pow_64)),
                    static_cast<uint64_t>(coeffd / two_pow_64)};
                if (is_negative){
                    for (size_t j = 0; j < coeff_mod_count; j++){
                        dest[j] = seal::util::negate_uint_mod(seal::util::barrett_reduce_128(coeffu, coeff_modulus[j]),
                                coeff_modulus[j]);
                    }
                }else{
                    for (size_t j = 0; j < coeff_mod_count; j++){
                        dest[j] = seal::util::barrett_reduce_128(coeffu, coeff_modulus[j]);
                    }
                }
            } else {
                auto decompose_single_coeff = 
                    [](const seal::SEALContext::ContextData & local_context_data,
                            const std::uint64_t * local_value,
                            std::uint64_t* local_destination,
                            seal::util::MemoryPool& local_pool){
                        auto & local_parms = local_context_data.parms();
                        auto & local_coeff_modulus = local_parms.coeff_modulus();
                        std::size_t local_coeff_mod_count = local_coeff_modulus.size();

                        auto value_copy(seal::util::allocate_uint(local_coeff_mod_count, local_pool));
                        for (std::size_t j = 0; j < local_coeff_mod_count; j++){
                            seal::util::set_uint_uint(local_value, local_coeff_mod_count, value_copy.get());
                            for (std::size_t k = local_coeff_mod_count - 1; k--; ){
                                value_copy[k] = seal::util::barrett_reduce_128(value_copy.get() + k, local_coeff_modulus[j]);
                            }
                            local_destination[j] = value_copy[0];
                        }
                    };
                auto coeffu(seal::util::allocate_uint(coeff_mod_count, pool));
                auto decomp_coeffu(seal::util::allocate_uint(coeff_mod_count, pool));

                seal::util::set_zero_uint(coeff_mod_count, coeffu.get());
                auto coeffu_ptr = coeffu.get();
                while (coeffd >= 1){
                    *coeffu_ptr++ = static_cast<uint64_t>(fmod(coeffd, two_pow_64));
                    coeffd /= two_pow_64;
                }
                decompose_single_coeff(context_data, coeffu.get(), decomp_coeffu.get(), pool);
                if (is_negative) {
                    for (size_t j = 0; j < coeff_mod_count; j++){
                        dest[j] = seal::util::negate_uint_mod(decomp_coeffu[j], coeff_modulus[j]);
                    }
                } else {
                    for (size_t j = 0; j < coeff_mod_count; j++){
                        dest[j] = decomp_coeffu[j];
                    }
                }
            }
    }

    inline void add_poly_scalar_coeffmod(const std::uint64_t* poly,
            std::size_t coeff_count,
            std::uint64_t scalar,
            const seal::SmallModulus& modulus,
            std::uint64_t* result) {
            const uint64_t modulus_value = modulus.value();

            for (; coeff_count--; result++, poly++) {
                        // Explicit inline
                        // // result[i] = add_uint_uint_mod(poly[i], scalar, modulus);



                std::uint64_t sum = *poly + scalar;
                *result = sum - (modulus_value &
                                                 static_cast<std::uint64_t>(-static_cast<std::int64_t>(sum >= modulus_value)));
            }
    }


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
                    double arg1,
                    std::shared_ptr<hewrapper::SEALEngine> engine){
        if(arg0.rescale_required){
                engine->get_evaluator()->rescale_to_next_inplace(arg0.ciphertext());
                arg0.rescale_required = false;
        }
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

    void seal_scalar_add(SEALCiphertext &arg0, double scalar, SEALCiphertext &out){
        out = arg0;
        if(scalar == 0)return;
        seal_scalar_add_inplace(out, scalar);

    }

    void seal_scalar_add_inplace(SEALCiphertext &arg0, double scalar){
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        std::shared_ptr<seal::SEALContext> context = engine->get_context()->get_sealcontext();
        auto& context_data = *context->get_context_data(arg0.ciphertext().parms_id());
        auto& parms = context_data.parms();
        auto& coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();

        std::vector<std::uint64_t> plaintext_vals(coeff_mod_count, 0);
        double scale = arg0.scale();
        encode(scalar, scale, arg0.ciphertext().parms_id(), plaintext_vals, engine);

        for (size_t j = 0; j < coeff_mod_count; j++) {
            //  Add poly scalar instead of poly poly
            add_poly_scalar_coeffmod(arg0.ciphertext().data() + (j * coeff_count), coeff_count,
                    plaintext_vals[j], 
                    coeff_modulus[j],      
                    arg0.ciphertext().data() + (j * coeff_count));
        }
    }
// still has bug.
    void multiply_plain_simple_mod(SEALCiphertext& arg0, 
        double scalar, 
        SEALCiphertext & dest, 
        std::shared_ptr<hewrapper::SEALEngine> engine,
        seal::MemoryPoolHandle pool){
        std::shared_ptr<seal::SEALContext> context = engine->get_context()->get_sealcontext();
        if(engine->lazy_mode()){
                _multiply_rescale(arg0, scalar, engine);
        }

        auto& context_data = *context->get_context_data(arg0.ciphertext().parms_id());
        auto& parms = context_data.parms();
        auto& coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();
        size_t encrypted_ntt_size = arg0.ciphertext().size();
        dest.ciphertext() = seal::Ciphertext(context, arg0.ciphertext().parms_id(), arg0.ciphertext().size());
        dest.ciphertext().resize(arg0.ciphertext().size());
        dest.ciphertext().is_ntt_form() = arg0.ciphertext().is_ntt_form();
        std::vector<std::uint64_t> plaintext_vals(coeff_mod_count, 0);
        double scale = arg0.scale();
        double new_scale = scale * scale;
        cout << "encode..." << endl;
        encode(scalar, scale, arg0.ciphertext().parms_id(), plaintext_vals, engine);
        std::uint64_t* src = const_cast<std::uint64_t*>(arg0.ciphertext().data());
        std::uint64_t* out = dest.ciphertext().data();
        cout << "start..." << endl;
        for(size_t i = 0; i < encrypted_ntt_size; i++){
            for (size_t j = 0; j < coeff_mod_count; j++){
            std::uint64_t value = plaintext_vals[j];
#pragma omp simd
            for(size_t k = 0; k < coeff_count; k++){
        *out = *src * value;
        ++src;
        ++out;
            }
         }
        }
        cout << "end,,," << endl;
        dest.scale() =  new_scale;

        if (engine->lazy_mode()){
                arg0.rescale_required = true;
        }else{
                cout << "start rescale" << endl;
                engine->get_evaluator()->rescale_to_next_inplace(arg0.ciphertext());
                arg0.rescale_required = false;
                cout <<"finish rescale" << endl;
        }
    }


    void seal_scalar_multiply(SEALCiphertext & arg0, double scalar, SEALCiphertext &out, const seal::MemoryPoolHandle& pool){
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        if(engine->simple_mode()){
            multiply_plain_simple_mod(arg0, scalar, out, engine, std::move(pool));
            cout << "finish mul" <<endl;
        }else{
            out = arg0;
            seal_scalar_multiply_inplace(out, scalar, std::move(pool));
        }
    }

    void seal_scalar_multiply_inplace(SEALCiphertext &arg0, double scalar, const seal::MemoryPoolHandle& pool){
        std::shared_ptr<hewrapper::SEALEngine> engine = arg0.getSEALEngine();
        std::shared_ptr<seal::SEALContext> context = engine->get_context()->get_sealcontext();
        if(engine->lazy_mode()){
                _multiply_rescale(arg0, scalar, engine);
        }
        auto& context_data = *context->get_context_data(arg0.ciphertext().parms_id());
        auto& parms = context_data.parms();
        auto& coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();
        size_t encrypted_ntt_size = arg0.ciphertext().size();

        std::vector<std::uint64_t> plaintext_vals(coeff_mod_count, 0);
        double scale = arg0.scale();
        encode(scalar, scale, arg0.ciphertext().parms_id(),plaintext_vals, engine);
        double new_scale = scale * scale;
        for (size_t i = 0; i < encrypted_ntt_size; i++){
            for (size_t j = 0; j < coeff_mod_count; j++){
                if (coeff_modulus[j].value() < (1UL << 31U)){
                    multiply_poly_scalar_coeffmod64(arg0.ciphertext().data(i) + (j * coeff_count),
                            coeff_count, plaintext_vals[j],
                            coeff_modulus[j],
                            arg0.ciphertext().data(i) + (j * coeff_count));
                }else{
                    seal::util::multiply_poly_scalar_coeffmod(
                            arg0.ciphertext().data(i) + (j * coeff_count), coeff_count,
                            plaintext_vals[j],
                            coeff_modulus[j],
                            arg0.ciphertext().data(i) + (j * coeff_count));
                }
            }
        }
        arg0.scale() = new_scale;

        if (engine->lazy_mode()){
                arg0.rescale_required = true;
        }else{
                engine->get_evaluator()->rescale_to_next_inplace(arg0.ciphertext());
                arg0.rescale_required = false;
        }
    }

}
    
