#pragma once 

#include "boost/asio.hpp"
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include "IOChannel.hpp"
using std::string;

class NetIO: public IOChannel<NetIO> { public:
	NetIO(const char * address, int port, std::shared_ptr<SEALEngine> engine);

	void sync(int tmp);

	~NetIO();

	void flush();

	void send_ciphertext_internal(SEALCiphertext * ciphertext);
	
	int recv_ciphertext_internal(SEALCiphertext * ciphertext, bool is_add);

	void send_data_internal(const void * data, int len);

	void recv_data_internal(void  * data, int len);
	
	bool is_server;
    SEALCiphertext tmp;
	boost::system::error_code ec;
    boost::asio::io_context m_io_context;
    std::thread m_message_handling_thread;
    std::unique_ptr<boost::asio::ip::tcp::acceptor> m_acceptor;
	boost::asio::ip::tcp::socket consocket; 
	char * tmp_char_vector;
	boost::asio::ip::tcp::iostream stream;
	std::stringstream sstr; 
	std::shared_ptr<SEALEngine> m_engine;
	string addr;
	int port;
};
