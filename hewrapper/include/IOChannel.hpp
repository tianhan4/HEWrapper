#pragma once

#include <memory>
#include "SEALEngine.h"
#include "SEALHE.h"

enum remote_ops{
	OP_SIGM_FP,
	OP_TANH_FP,
	OP_MAX2D_FP,
	OP_CE_BIN_FP,
	OP_CE_MULTI_FP,
	OP_LOG_FP,
	OP_RELU_FP,
	OP_MSE_FP,
	OP_SOFTMAX_FP,
	OP_AVG_FP,
	OP_CE_BIN_NEG_FP,
	FP_________LINE,
	OP_SIGM_BP,
	OP_TANH_BP,
	OP_MAX2D_BP,
	OP_CE_BIN_BP,
	OP_CE_MULTI_BP,
	OP_LOG_BP,
	OP_RELU_BP,
	OP_MSE_BP,
	OP_SOFTMAX_BP,
	OP_AVG_BP,
	OP_CE_BIN_NEG_BP,
	BP_________LINE,
	OP_DP_DECRYPTION
};

#define is_fp(op)  ( op < FP_________LINE)

template<typename T> 
class IOChannel { public:
	uint64_t counter = 0;
	void send_data(const void * data, int nbyte) {
		counter +=nbyte;
		derived().send_data_internal(data, nbyte);
	}

	void recv_data(void * data, int nbyte) {
		derived().recv_data_internal(data, nbyte);
	}

	void send_ciphertext(int op, int layer, SEALCiphertext* ciphertext, int *dim, int dim_size, bool for_decryption=false) {
		//0.send op
		//1.send dim number
		//2.send dim
		//4.send ciphertext
		send_data(&op, sizeof(int));
		send_data(&layer, sizeof(int));
		send_data(&dim_size, sizeof(int));
		send_data(dim, sizeof(int)*dim_size);
		int number = 1;
		for (int j = 0; j < dim_size; j++)
			number *= dim[j];
		bool is_level_zero = false;
		std::shared_ptr<hewrapper::SEALEngine> engine = ciphertext->getSEALEngine();
		auto context = engine->get_context()->get_sealcontext();
		if(for_decryption){
			size_t level = context->get_context_data(ciphertext->ciphertext().parms_id())->chain_index();
			if(level == 0)
				is_level_zero = true;
		}
		for (int i = 0; i< number; i++){
			if((!is_level_zero) && (for_decryption)){
				engine->get_evaluator()->mod_switch_to_inplace(ciphertext[i].ciphertext(), context->last_parms_id());
			}
			derived().send_ciphertext_internal(ciphertext+i);
		}
	}

	size_t recv_ciphertext(SEALCiphertext* ciphertext, bool is_add = false) {
		int op, layer, dim_size;
		int dim[5];
		return recv_ciphertext(&op, &layer, ciphertext, dim, &dim_size, is_add);
	}
	
	size_t recv_ciphertext(int *op, int * layer, SEALCiphertext* ciphertext, int *dim, int *dim_size, bool is_add = false) {
		//0.recv op
		//1.recv dim number
		//2.recv dim
		//4.recv ciphertext
		recv_data(op, sizeof(int));
		recv_data(layer, sizeof(int));
		recv_data(dim_size, sizeof(int));
		recv_data(dim, sizeof(int)*(*dim_size));
		//cout << *op << endl;
		//cout << *dim_size << endl;
		//for (int i = 0; i< *dim_size; i++)
		//	cout << dim[i];
		//cout << endl;
		int number = 1;
		for (int j = 0; j < *dim_size; j++)
			number *= dim[j];
		for (int i = 0; i< number; i++){
			derived().recv_ciphertext_internal(ciphertext+i, is_add);
		}
		return number;
	}

	size_t recv_ciphertext(vector<SEALCiphertext> & ciphertext, bool is_add = false) {
		int op, layer, dim_size;
		int dim[5];
		return recv_ciphertext(&op, &layer, ciphertext, dim, &dim_size, is_add);
	}

	size_t recv_ciphertext(int *op, int *layer, vector<SEALCiphertext> & ciphertext_vector, int *dim, int *dim_size, bool is_add = false) {
		//0.recv op
		//1.recv dim number
		//2.recv dim
		//4.recv ciphertext
		recv_data(op, sizeof(int));
		recv_data(layer, sizeof(int));
		recv_data(dim_size, sizeof(int));
		recv_data(dim, sizeof(int)*(*dim_size));
		//cout << *op << endl;
		//cout << *dim_size << endl;
		//for (int i = 0; i< *dim_size; i++)
		//	cout << dim[i];
		//cout << endl;
		int count = 0;
		/*
		//check some bytes
		for(int i=0;i<30;i++){
			char b;
			recv_data(&b, 1);
			cout << i << ":" << int(b) <<  endl;
		}*/

		int number = 1;
		for (int j = 0; j < *dim_size; j++)
			number *= dim[j];
		while(ciphertext_vector.size() < number){
			SEALCiphertext tmp;
			ciphertext_vector.push_back(tmp);
		}
		for (int i = 0; i< number; i++){
			derived().recv_ciphertext_internal(&ciphertext_vector[i], is_add);
		}
		return number;
	}

	void send_plaintext(float* values, int *dim, int dim_size) {
		//1.send dim number
		//2.send dim
		//4.send values
		send_data(&dim_size, sizeof(int));
		send_data(dim, sizeof(int)*dim_size);
		int number = 1;
		for (int j = 0; j < dim_size; j++)
			number *= dim[j];
		send_data(values, number*sizeof(float));
	}

	size_t recv_plaintext(float* values, int *dim, int *dim_size) {
		//1.recv dim number
		//2.recv dim
		//4.recv values
		recv_data(dim_size, sizeof(int));
		recv_data(dim, sizeof(int)*(*dim_size));
		int number = 1;
		for (int j = 0; j < *dim_size; j++)
			number *= dim[j];
		recv_data(values, number*sizeof(float));
		return number;
	}

	private:
	T& derived() {
		return *static_cast<T*>(this);
	}
};