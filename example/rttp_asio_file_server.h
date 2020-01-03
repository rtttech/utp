#ifndef __RTTP_ASIO_FILE_SERVER__
#define __RTTP_ASIO_FILE_SERVER__

#include <deque>
#include <set>
#include <map>
#include <assert.h>
#include <string.h>
#include <memory>
#include <thread>
#include <unordered_map>
#include <strstream>
#include <cstdlib>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/filesystem.hpp>
#include <boost/lockfree/spsc_queue.hpp>
#include <chrono>
#include <boost/range/iterator_range.hpp>
#include <boost/asio/steady_timer.hpp>
#include <algorithm>
#include <functional>
#include <time.h>

using boost::asio::ip::udp;
using namespace boost;
using namespace std;

class boost_rttp_server;
class async_file_server;
class async_file_operator;

class client
{
public:
	virtual ~client() {}
};

struct rtsocket_server_context 
{
	bool run = true;
	SOCKET socket = -1;
	uint64_t total_send = 0;
	uint64_t connection_num = 0;
	uint64_t total_waiting_send_num = 0;
	std::deque<std::shared_ptr<udp_pkt_send_item>> udp_send_deq;
	std::deque<std::shared_ptr<udp_pkt_send_item>> udp_recv_deq;

	char state[4096] = { 0 };
};


class async_file_handle
{
public:
	FILE* fp = NULL;
	uint64_t size = 0;
	time_t last_update = 0;
	std::set<boost::shared_ptr<async_file_operator>> operators;
};

class async_file_operator
{
public:
	virtual void handle_open_file_complete(boost::shared_ptr<async_file_handle> handle_ptr, int err) = 0;
	virtual void handle_read_file_complete(char* buffer, int size) = 0;
};


class async_file_server
{
public:
	async_file_server(asio::io_service& io_context);
	~async_file_server();

	void start(const char* path);
	void stop();

	const std::string& work_path() const { return work_path_; }
	//uint64_t get_file_size(const std::string& file);

	void async_open_file(boost::shared_ptr<async_file_operator> initiator, const std::string& path_file, uint64_t offset = 0);
	void async_read_file(boost::shared_ptr<async_file_operator> initiator, boost::shared_ptr<async_file_handle> handle_ptr, uint64_t offset, char* buffer, int size);
	void async_close_file(boost::shared_ptr<async_file_operator> initiator, boost::shared_ptr<async_file_handle> handle_ptr);

private:
	static int file_access_thread_proc(void* param);

private:
	struct async_file_op
	{
		enum op_cmd { OPC_OPEN, OPC_READ, OPC_CLOSE, OPC_EXIT };
		boost::shared_ptr<async_file_operator> initiator;
		boost::shared_ptr<async_file_handle> handle_ptr;
		int cmd;
		std::string file;
		uint64_t offset = 0;
		char* buffer = NULL;
		int size = 0;
	};

private:
	asio::io_service &io_context_;
	boost::lockfree::spsc_queue<boost::shared_ptr<async_file_op>, boost::lockfree::capacity<256>> file_op_queue_;
	std::string work_path_;
	std::map<std::string, boost::shared_ptr<async_file_handle>> files_;

	boost::shared_ptr<std::thread> work_thread_ptr_;
};

class client_factory
{
public:
	virtual boost::shared_ptr<client> create_client(RTSOCKET socket, boost_rttp_server& server) = 0;
	virtual void close_client(boost::shared_ptr<client> client_ptr) = 0;
	virtual boost::shared_ptr<client> get_client(RTSOCKET socket) = 0;
	virtual std::vector<boost::shared_ptr<client>> get_all_client() = 0;
	virtual std::vector<RTSOCKET> get_all_socket() = 0;
};


class download_file_client : public socket_io_info, public boost::enable_shared_from_this<download_file_client>, public async_file_operator, public client
{
public:
	download_file_client(asio::io_service& io_ctx, boost_rttp_server& server, async_file_server& file_server,  RTSOCKET socket);
	~download_file_client();

	void async_read_file();
	void close();

	virtual void handle_open_file_complete(boost::shared_ptr<async_file_handle> handle_ptr, int err);
	virtual void handle_read_file_complete(char* buffer, int size);
	
public:
	std::string request_lines_;
	uint64_t req_file_pos_ = 0;
	uint64_t cur_file_pos_ = 0;
	bool reading_file_ = false;
	boost::shared_ptr<async_file_handle> handle_ptr_;

	uint64_t file_size_ = 0;
	//uint64_t sent_size_ = 0;
	asio::io_service& io_context_;
	RTSOCKET rttp_socket_;

	boost_rttp_server& rttp_server_;
	async_file_server& file_server_;

};

class boost_rttp_server
{
public:
	boost_rttp_server(asio::io_service& io_context, short port, client_factory& clnt_factory);

	void do_receive();
	void do_send();

	void on_timer(system::error_code error);

public:
	rtsocket_server_context server_ctx_;
	client_factory &client_factory_;
private:
	udp::socket socket_;
	udp::endpoint sender_endpoint_;
	asio::io_service &io_context_;
	asio::steady_timer timer_;


	enum { max_length = 2048 };
	char data_[max_length];

	bool sending_ = false;
	char state[4096] = { 0 };
};

class download_file_client_factory : public client_factory
{
public:
	download_file_client_factory(asio::io_service& io_ctx, async_file_server& file_server);
	virtual ~download_file_client_factory();

	virtual boost::shared_ptr<client> create_client(RTSOCKET socket, boost_rttp_server& server);
	virtual void close_client(boost::shared_ptr<client> client_ptr);
	virtual boost::shared_ptr<client> get_client(RTSOCKET socket);
	virtual std::vector<boost::shared_ptr<client>> get_all_client();
	virtual std::vector<RTSOCKET> get_all_socket();
private:
	asio::io_service& io_ctx_;
	async_file_server& file_server_;

	std::unordered_map<RTSOCKET, boost::shared_ptr<download_file_client>> client_map_;
};

#endif // !__RTTP_ASIO_FILE_SERVER__
