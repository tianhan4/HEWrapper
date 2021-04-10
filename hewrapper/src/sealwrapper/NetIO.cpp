
#include "NetIO.h"
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <sstream>
using std::string;

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <boost/asio/impl/src.hpp>

const static int NETWORK_BUFFER_SIZE = 1024 * 1024;


NetIO::NetIO(const char * address, int port, std::shared_ptr<SEALEngine> engine):sstr{std::stringstream::out | std::stringstream::in | std::stringstream::binary},
m_engine{engine},consocket{m_io_context}{
    tmp_char_vector = new char[1000000];
    this->port = port & 0xFFFF;
    is_server = (address == nullptr);
    this->m_engine = engine;
    if (address == nullptr) {
        std::cout << "Server accepting connections." << endl;
        boost::asio::ip::tcp::resolver resolver(m_io_context);
        //boost::asio::ip::tcp::endpoint server_endpoints(boost::asio::ip::tcp::v4(), port);
        //used for gpu06
        boost::asio::ip::tcp::endpoint server_endpoints(boost::asio::ip::address::from_string("10.0.3.1"), port);
        m_acceptor = std::make_unique<boost::asio::ip::tcp::acceptor>(
            m_io_context, server_endpoints);
        boost::asio::socket_base::reuse_address option(true);
        m_acceptor->set_option(option);

        stream.socket() = m_acceptor->accept(ec);			
        if (ec){
            cout << ec << endl;
            assert(false && "connect failed!!");
        }
        /*m_message_handling_thread = std::thread([this]() {
            try {
            m_io_context.run();
            } catch (std::exception& e) {
            cerr << e.what();
            assert(false && "Server error handling thread: ");
            }
        });*/
    }
    else {
        boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::address::from_string(address), port);
        cout  << "Trying to connect TCP client" << address << port << endl;
        consocket.connect(endpoint, ec);
        if (ec){
            cout << ec.message() << endl;
            assert(false && "connect failed!..!!");
        }
        stream.socket() = std::move(consocket);
        m_io_context.run(); 
    }
    //Nothing needs to be done about buffer???
    std::cout << "connected\n";
    sync(123456);
}

void NetIO::sync(int tmp) {
    cout << "sync" << endl;
    if(is_server) {
        send_data_internal(&tmp, 1);
        recv_data_internal(&tmp, 1);
        cout << tmp << endl;
    } else {
        recv_data_internal(&tmp, 1);
        cout << tmp << endl;
        send_data_internal(&tmp, 1);
        flush();
    }
}

NetIO::~NetIO(){
    delete []tmp_char_vector;
    cout << "Closing connection." << endl;
    stream.flush();
    stream.close();
}

void NetIO::flush() {
    stream.flush();
}

void NetIO::send_ciphertext_internal(SEALCiphertext * ciphertext){
    sstr.seekp(ios_base::beg);
    std::streamoff setoff = ciphertext->save(sstr);
    //cout << "setoff" << setoff << endl;
    int seto_t = int(sstr.tellp());
    //cout << seto_t << endl;
    assert(seto_t==setoff);
    send_data_internal(&seto_t, sizeof(int));
    stream.write(sstr.str().c_str(), seto_t);
}

int NetIO::recv_ciphertext_internal(SEALCiphertext * ciphertext, bool is_add){
    int offset;
    recv_data_internal(&offset, sizeof(int));
    //cout << "offset:" << offset << endl;
    recv_data_internal(tmp_char_vector, offset);
    sstr.seekp(ios_base::beg);
    sstr.write(tmp_char_vector, offset);
    //cout << "string size:" << sstr.str().size() << endl;
    sstr.seekg(ios_base::beg);
    if(is_add){
        tmp.load(sstr,this->m_engine);
        tmp.init(m_engine);
        seal_add_inplace(*ciphertext, tmp);
    }
    else{
        ciphertext->load(sstr,this->m_engine);
        ciphertext->init(m_engine);
    }
    return offset;
}

void NetIO::send_data_internal(const void * data, int len) {
    stream.write(static_cast<const char *>(data), len);
}

void NetIO::recv_data_internal(void  * data, int len) {
    stream.read(static_cast<char*>(data), len);

}