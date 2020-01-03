#include "utp_socket_c.h"
#include "os_common.h"
#include "http.h"
#include "rttp_asio_file_server.h"
#include <thread>
#include <stdio.h>

using namespace std;


int rtsocket_send_data(RTSOCKET socket, socket_io_info& si)
{
	int send = 0;
	while (si.send_deq.size() > 0) {
		socket_send_item& item = *si.send_deq[0];

		int send_bytes = rt_send(socket, item.send_buffer + item.send_buff_pos, item.send_buff_len - item.send_buff_pos, 0);
		if (send_bytes <= 0) {
			return send;
		}
		else {
			send += send_bytes;
			item.send_buff_pos += send_bytes;
			//cout << "send " << send_bytes << " bytes, total send "<<item.send_buff_pos << endl;
			if (item.send_buff_pos == item.send_buff_len) {
				si.send_deq.pop_front();
			}
		}
	}

	return send;
}


download_file_client::download_file_client(asio::io_service& io_ctx, boost_rttp_server& server, async_file_server& file_server, RTSOCKET socket)
	: io_context_(io_ctx), rttp_socket_(socket), rttp_server_(server), file_server_(file_server), req_file_pos_(0), cur_file_pos_(0)
{

}

download_file_client::~download_file_client()
{
	
	if (handle_ptr_ != NULL) {
		file_server_.async_close_file(shared_from_this(), handle_ptr_);
		handle_ptr_.reset();
	}
}

void download_file_client::async_read_file()
{
	if (handle_ptr_ == NULL || reading_file_ || cur_file_pos_ >= file_size_)
		return;

	int buff_size = min((uint64_t)2 * 1024 * 1024, file_size_ - cur_file_pos_);
	char* buffer = new char[buff_size];

	reading_file_ = true;
	file_server_.async_read_file(shared_from_this(), handle_ptr_, cur_file_pos_, buffer, buff_size);
}

void download_file_client::close()
{
	if (handle_ptr_ != NULL) {
		file_server_.async_close_file(shared_from_this(), handle_ptr_);
		handle_ptr_.reset();
	}
    
    if (rttp_socket_ != 0) {
        rt_close(rttp_socket_);
        rttp_socket_ = 0;
    }
}

void download_file_client::handle_read_file_complete(char* buffer, int bytes)
{
	reading_file_ = false;

	if (bytes > 0) {
		send_deq.push_back(std::shared_ptr<socket_send_item>(new socket_send_item(buffer, bytes)));
		int ret = rtsocket_send_data(rttp_socket_, *this);
		
		cur_file_pos_ += bytes;

		if (file_size_ > 0 && cur_file_pos_ == file_size_ && send_deq.size() == 0) {
			//send file completed
			rttp_server_.client_factory_.close_client(shared_from_this());
		}
		else {
			if (send_deq.size() < 3) {
				async_read_file();
			}
		}
	}
	else {
		cout << "read file failed" << endl;
		delete buffer;
		file_server_.async_close_file(shared_from_this(), handle_ptr_);
		handle_ptr_.reset();
		rttp_server_.client_factory_.close_client(shared_from_this());
	}
}

void download_file_client::handle_open_file_complete(boost::shared_ptr<async_file_handle> handle_ptr, int err)
{
	if (err == 0) {
		
		handle_ptr_ = handle_ptr;

		file_size_ = handle_ptr->size;

		char *resp_head = new char[1024];
		std::strstream resp_stream(resp_head, 1024);

		if (req_file_pos_ == 0) {
			resp_stream << "HTTP/1.1 200 OK\r\n";
		}
		else {
			resp_stream << "HTTP/1.1 206 Partial Content\r\n";
			resp_stream << "Content-Range: bytes " << req_file_pos_ << "-" << file_size_-1 << "/" << file_size_ << "\r\n";
		}
		resp_stream << "Content-Length: " << file_size_ << "\r\n";
		resp_stream << "Server: http-utp server\r\n";
		resp_stream << "\r\n";

		send_deq.push_back(std::shared_ptr<socket_send_item>(new socket_send_item(resp_head, resp_stream.pcount())));

		rtsocket_send_data(rttp_socket_, *this);

		async_read_file();
	}
	else {
        char *resp_head = new char[256];
        std::strstream resp_stream(resp_head, 256);
        resp_stream << "HTTP/1.1 404 ERROR open_file_failed\r\n\r\n"<< endl;
        
        send_deq.push_back(std::shared_ptr<socket_send_item>(new socket_send_item(resp_head, resp_stream.pcount())));
        
        state = socket_io_info::WAITING_CLOSE;
        
        rtsocket_send_data(rttp_socket_, *this);
        if (send_deq.size() == 0) {
            rttp_server_.client_factory_.close_client(shared_from_this());
        }
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
async_file_server::async_file_server(asio::io_service& io_context)
	:io_context_(io_context)
{

}

async_file_server::~async_file_server()
{

}

void async_file_server::start(const char* path)
{
	work_path_ = path;

	if (work_thread_ptr_ != NULL)
		return;

	work_thread_ptr_.reset(new std::thread(file_access_thread_proc, this));
	cout << "working..." << endl;
	cout << "home path: "<<work_path_ << endl;
}

void async_file_server::stop()
{
	boost::shared_ptr<async_file_op> op_ptr(new async_file_op());
	op_ptr->cmd = async_file_op::OPC_EXIT;
	file_op_queue_.push(op_ptr);

	work_thread_ptr_->join();

	work_thread_ptr_.reset();
}

void async_file_server::async_open_file(boost::shared_ptr<async_file_operator> initiator, const std::string& path_file, uint64_t offset)
{
	boost::shared_ptr<async_file_op> op_ptr(new async_file_op());
	op_ptr->cmd = async_file_op::OPC_OPEN;
	op_ptr->initiator = initiator;
	op_ptr->file = path_file;
	op_ptr->offset = offset;

	file_op_queue_.push(op_ptr);
}

void async_file_server::async_read_file(boost::shared_ptr<async_file_operator> initiator, boost::shared_ptr<async_file_handle> handle_ptr, uint64_t offset, char* buffer, int size)
{
	boost::shared_ptr<async_file_op> op_ptr(new async_file_op());
	op_ptr->cmd = async_file_op::OPC_READ;
	op_ptr->initiator = initiator;
	op_ptr->handle_ptr = handle_ptr;
	op_ptr->offset = offset;
	op_ptr->buffer = buffer;
	op_ptr->size = size;

	file_op_queue_.push(op_ptr);
}

void async_file_server::async_close_file(boost::shared_ptr<async_file_operator> initiator, boost::shared_ptr<async_file_handle> handle_ptr)
{
	boost::shared_ptr<async_file_op> op_ptr(new async_file_op());
	op_ptr->cmd = async_file_op::OPC_CLOSE;
	op_ptr->initiator = initiator;
	op_ptr->handle_ptr = handle_ptr;

	file_op_queue_.push(op_ptr);

}

int async_file_server::file_access_thread_proc(void* param)
{
	async_file_server* this_ptr = (async_file_server*)param;

	while (true) {
		if (!this_ptr->file_op_queue_.empty()) {
			boost::shared_ptr<async_file_op> op_ptr;
			this_ptr->file_op_queue_.pop(op_ptr);

			if (op_ptr->cmd == async_file_op::OPC_READ) {

				if (op_ptr->handle_ptr->operators.find(op_ptr->initiator) == op_ptr->handle_ptr->operators.end()) {
					//file has changed or other reasons
					this_ptr->io_context_.post(boost::bind(&async_file_operator::handle_read_file_complete, op_ptr->initiator, op_ptr->buffer, -1));
				}
				else {
					int seek_ret = fseek(op_ptr->handle_ptr->fp, op_ptr->offset, SEEK_SET);
					size_t ret = fread(op_ptr->buffer, 1, op_ptr->size, op_ptr->handle_ptr->fp);
					int err = ferror(op_ptr->handle_ptr->fp);
					if (ret > 0) {
						this_ptr->io_context_.post(boost::bind(&async_file_operator::handle_read_file_complete, op_ptr->initiator, op_ptr->buffer, ret));
					}
					else {
						cout << "read file failed, error:" << err << endl;
						this_ptr->io_context_.post(boost::bind(&async_file_operator::handle_read_file_complete, op_ptr->initiator, op_ptr->buffer, -1));
					}
				}
			}
			else if (op_ptr->cmd == async_file_op::OPC_OPEN) {
				boost::shared_ptr<async_file_handle> handle_ptr;
				std::map<std::string, boost::shared_ptr<async_file_handle>>::iterator iter = this_ptr->files_.find(op_ptr->file);
				if (iter == this_ptr->files_.end()) {
					handle_ptr.reset(new async_file_handle());
					this_ptr->files_[op_ptr->file] = handle_ptr;
				}
				else {
					handle_ptr = iter->second;
				}
				
				if (handle_ptr->fp == NULL) {
					handle_ptr->fp = fopen(op_ptr->file.c_str(), "rb");
					uint64_t size = 0;
					if (handle_ptr->fp != NULL) {
						handle_ptr->size = filesystem::file_size(filesystem::path(op_ptr->file));
						handle_ptr->last_update = filesystem::last_write_time(filesystem::path(op_ptr->file));

						handle_ptr->operators.insert(op_ptr->initiator);
						this_ptr->io_context_.post(boost::bind(&async_file_operator::handle_open_file_complete, op_ptr->initiator, handle_ptr, 0));
					}
					else {
						//open file failed
						this_ptr->io_context_.post(boost::bind(&async_file_operator::handle_open_file_complete, op_ptr->initiator, boost::shared_ptr<async_file_handle>(), -1));
					}
				}
				else {
					handle_ptr->operators.insert(op_ptr->initiator);
					this_ptr->io_context_.post(boost::bind(&async_file_operator::handle_open_file_complete, op_ptr->initiator, handle_ptr, 0));
				}
			
			}
			else if (op_ptr->cmd == async_file_op::OPC_CLOSE) {
				op_ptr->handle_ptr->operators.erase(op_ptr->initiator);
				if (op_ptr->handle_ptr->operators.size() == 0) {
					fclose(op_ptr->handle_ptr->fp);
					op_ptr->handle_ptr->fp = NULL;
				}
			}
			else if (op_ptr->cmd == async_file_op::OPC_EXIT) {
				break;
			}
			else {
				assert(false);
			}
		}
		else {
			this_thread::sleep_for(chrono::milliseconds(10));
		}
	}

	return 0;
}


boost_rttp_server::boost_rttp_server(asio::io_service& io_context, short port, client_factory& clnt_factory)
	: socket_(io_context, udp::endpoint(udp::v4(), port)), io_context_(io_context), timer_(io_context), client_factory_(clnt_factory)
{
	boost::asio::socket_base::send_buffer_size option(2*1024*1024);
	socket_.set_option(option);

	do_receive();
    
    timer_.expires_from_now(std::chrono::milliseconds(10));
	timer_.async_wait(boost::bind(&boost_rttp_server::on_timer, this, asio::placeholders::error));
}

void boost_rttp_server::on_timer(system::error_code error)
{
	static time_t last_update_internal_state = time(NULL);

	std::vector<RTSOCKET> client_vec = client_factory_.get_all_socket();

	if (client_vec.size() == 1) {
		//for debug transfer performance
		if (time(NULL) - last_update_internal_state > 1) {
			last_update_internal_state = time(NULL);
			int ret = rt_state_desc(client_vec[0], server_ctx_.state, sizeof(server_ctx_.state)-1);
			if (ret > 0) {
				server_ctx_.state[ret] = 0;
			}
			else {
				server_ctx_.state[0] = 0;
			}
		}
	}
	else {
		server_ctx_.state[0] = 0;
	}

	rt_tick();

	timer_.expires_from_now(std::chrono::milliseconds(10));
	timer_.async_wait(boost::bind(&boost_rttp_server::on_timer, this, asio::placeholders::error));
}

void boost_rttp_server::do_receive()
{
	socket_.async_receive_from(asio::buffer(data_, max_length), sender_endpoint_, [this](system::error_code ec, std::size_t bytes_recvd)
	{
		if (!ec && bytes_recvd > 0)
		{
			RTSOCKET socket = rt_incoming_packet(data_, bytes_recvd, (const char*)sender_endpoint_.data(), sender_endpoint_.size(), this);
			if (socket != NULL && client_factory_.get_client(socket) == NULL) {
				cout << "incoming socket " << socket << endl;

				int mode = RTSM_HIGH_THROUGHPUT;
				rt_setsockopt(socket, RTSO_MODE, (char*)&mode, sizeof(mode));
				client_factory_.create_client(socket, *this);
			}
		}
		else {
			std::cout << "receive failed" << ec << endl;
		}

		if (server_ctx_.run)
		{
			do_receive();
		}
	});
}

void boost_rttp_server::do_send()
{
	if (sending_ || server_ctx_.udp_send_deq.size() == 0)
		return;

	sending_ = true;

	udp::endpoint remote_endpoint;
	memcpy(remote_endpoint.data(), (void*)&server_ctx_.udp_send_deq[0]->addr, server_ctx_.udp_send_deq[0]->addr_len);
	socket_.async_send_to(asio::buffer(server_ctx_.udp_send_deq[0]->buffer, server_ctx_.udp_send_deq[0]->len), sender_endpoint_,
		[this](system::error_code ec, std::size_t bytes_sent)
	{
		if (ec)
			std::cout << "send failed" << ec << endl;

		sending_ = false;
		server_ctx_.udp_send_deq.pop_front();

		if (server_ctx_.run && server_ctx_.udp_send_deq.size() > 0) {
			do_send();
		}
	});
}


download_file_client_factory::download_file_client_factory(asio::io_service& io_ctx, async_file_server& file_server)
	:io_ctx_(io_ctx), file_server_(file_server)
{
}

download_file_client_factory::~download_file_client_factory()
{
	
}

boost::shared_ptr<client> download_file_client_factory::create_client(RTSOCKET socket, boost_rttp_server& server)
{
	boost::shared_ptr<download_file_client> client_ptr(new download_file_client(io_ctx_, server, file_server_, socket));

	client_map_[socket] = client_ptr;

	return boost::static_pointer_cast<client>(client_ptr);
}

boost::shared_ptr<client> download_file_client_factory::get_client(RTSOCKET socket)
{
	std::unordered_map<RTSOCKET, boost::shared_ptr<download_file_client>>::iterator iter = client_map_.find(socket);
	if (iter == client_map_.end()) {
		return boost::shared_ptr<client>();
	}
	else {
		return iter->second;
	}
}

void download_file_client_factory::close_client(boost::shared_ptr<client> client_ptr)
{
	boost::shared_ptr<download_file_client> download_client_ptr = boost::static_pointer_cast<download_file_client>(client_ptr);
	client_map_.erase(download_client_ptr->rttp_socket_);
	download_client_ptr->close();
}

std::vector<boost::shared_ptr<client>> download_file_client_factory::get_all_client()
{
	std::vector<boost::shared_ptr<client>> vec;
	for (auto c : client_map_) {
		vec.push_back(c.second);
	}

	return vec;
}

std::vector<RTSOCKET> download_file_client_factory::get_all_socket()
{
	std::vector<RTSOCKET> vec;
	for (auto c : client_map_) {
		vec.push_back(c.first);
	}

	return vec;
}

void on_rtsocket_write(RTSOCKET socket)
{
	boost_rttp_server *server_ptr = (boost_rttp_server *)rt_get_userdata(socket);
	rtsocket_server_context *ctx_ptr = &server_ptr->server_ctx_;
	boost::shared_ptr<download_file_client> client_ptr = boost::static_pointer_cast<download_file_client>(server_ptr->client_factory_.get_client(socket));

	socket_io_info &si = *client_ptr;

	int ret = rtsocket_send_data(socket, si);
    
    if (si.state == socket_io_info::WAITING_CLOSE && si.send_deq.size() == 0) {
        server_ptr->client_factory_.close_client(client_ptr);
        return;
    }

	if (client_ptr->file_size_ > 0 && client_ptr->cur_file_pos_ == client_ptr->file_size_ && client_ptr->send_deq.size() == 0) {
		//send file completed
		server_ptr->client_factory_.close_client(client_ptr);
	}
	else {
		if (si.send_deq.size() < 3) {
			client_ptr->async_read_file();
		}
	}
}

int recv_request_line(RTSOCKET socket, socket_io_info& si)
{
	while (si.recv_buff_pos < si.recv_buff_len) {
		int ret = rt_recv(socket, si.recv_buffer + si.recv_buff_pos, 1, 0);
		if (ret > 0) {
			si.recv_buff_pos += ret;

			if (si.recv_buffer[si.recv_buff_pos - 1] == '\n') {
				return si.recv_buff_pos;
			}
		}
		else {
			return ret;
		}
	}

	return -2;
}

void on_rtsocket_read(RTSOCKET socket)
{
	boost_rttp_server *server_ptr = (boost_rttp_server *)rt_get_userdata(socket);
	rtsocket_server_context *ctx_ptr = &server_ptr->server_ctx_;
	boost::shared_ptr<download_file_client> client_ptr = boost::static_pointer_cast<download_file_client>(server_ptr->client_factory_.get_client(socket));
	socket_io_info& si = *client_ptr;

	if (si.recv_buffer == NULL) {
		si.recv_buff_pos = 0;
		si.recv_buff_len = 4096;
		si.recv_buffer = new char[si.recv_buff_len];
	}


	while (true) {
		int ret = recv_request_line(socket, si);

		if (ret > 0) {
			//receive request line success
			std::string line(si.recv_buffer, si.recv_buff_pos);
			client_ptr->request_lines_ += line;

			si.recv_buff_pos = 0;

			bool error_occur = false;
			std::string error_msg = "";

			if (line == "\n" || line == "\r\n") {
				HttpRequest req;
				if (req.Decode(client_ptr->request_lines_.c_str(), client_ptr->request_lines_.size())) {
					std::string path_file = (filesystem::path(client_ptr->file_server_.work_path()) / filesystem::path(req.GetReqPathFile())).string();

					int64_t offset = 0;
					int64_t end = 0;
					std::string range = req.GetHttpRequestField("Range");

					if (range.size() > 0) {
						if (!Http::DecodeHttpRequestRangeLine(range, offset, end)) {
							error_occur = true;
							error_msg = "invalid http range request\n";
						}
					}

					if (!error_occur) {
						client_ptr->req_file_pos_ = offset;
						client_ptr->cur_file_pos_ = offset;
						client_ptr->file_server_.async_open_file(client_ptr, path_file, offset);
					}
				}
				else {
					error_occur = true;
					error_msg = "invalid request";
				}

			}
			else {
				continue;//
			}

			if (error_occur) {
				char *resp_head = new char[1024];
				std::strstream resp_stream(resp_head, 1024);

				resp_stream << "HTTP/1.1 400 ERROR" + error_msg + "\r\n\r\n" << std::endl;
				si.state = socket_io_info::WAITING_CLOSE;

				std::shared_ptr<socket_send_item> ptr(new socket_send_item(resp_head, resp_stream.pcount()));
				si.send_deq.push_back(ptr);

				rtsocket_send_data(socket, si);
				if (si.send_deq.size() == 0) {
					server_ptr->client_factory_.close_client(client_ptr);
				}
				break;
			}

		}
		else if (ret == -1) {
			break;
		}
		else {
			server_ptr->client_factory_.close_client(client_ptr);
			cout << "recv request error: " << ret << endl;
			break;
		}
	}
}

void on_rtsocket_connect(RTSOCKET socket)
{
	boost_rttp_server *server_ptr = (boost_rttp_server *)rt_get_userdata(socket);
	rtsocket_server_context *ctx_ptr = &server_ptr->server_ctx_;

	on_rtsocket_write(socket);
}


void on_rtsocket_error(RTSOCKET socket)
{
	boost_rttp_server *server_ptr = (boost_rttp_server *)rt_get_userdata(socket);
	rtsocket_server_context *ctx_ptr = &server_ptr->server_ctx_;
	boost::shared_ptr<download_file_client> client_ptr = boost::static_pointer_cast<download_file_client>(server_ptr->client_factory_.get_client(socket));

	int errcode = rt_get_error(socket);
	cout << "socket " << socket << " error " << errcode << endl;

	server_ptr->client_factory_.close_client(client_ptr);
}

void on_rtsocket_event(RTSOCKET socket, int event)
{
	switch (event) {
	case RTTP_EVENT_CONNECT:
		on_rtsocket_connect(socket);
		return;
	case RTTP_EVENT_READ:
		on_rtsocket_read(socket);
		return;
	case RTTP_EVENT_WRITE:
		on_rtsocket_write(socket);
		return;
	case RTTP_EVENT_ERROR:
		on_rtsocket_error(socket);
		return;
	}
}

void packet_send_imp(RTSOCKET socket, const char * data, int len, const char * sa, int sock_len)
{
	boost_rttp_server *server_ptr = (boost_rttp_server *)rt_get_userdata(socket);
	rtsocket_server_context *ctx_ptr = &server_ptr->server_ctx_;

	std::shared_ptr<udp_pkt_send_item> ptr(new udp_pkt_send_item(data, len, (struct sockaddr *)sa, sock_len));
	ctx_ptr->udp_send_deq.push_back(ptr);

	server_ptr->do_send();
}


int main_func(asio::io_service *io_service)
{

	rt_init(NULL, 0);
	rt_set_callback(on_rtsocket_event, packet_send_imp);

	io_service->run();

	return 0;
}

int main(int argc, char* argv[])
{
	try
	{
		if (argc != 3)
		{
			std::cerr << "Usage: program <listen port> <path>";
			return 1;
		}

		filesystem::path work_path = argv[2];
		work_path = filesystem::canonical(work_path);

		unsigned short port = std::atoi(argv[1]);

		asio::io_service io_context;
		async_file_server file_server(io_context);
		file_server.start(work_path.string().c_str());

		download_file_client_factory df_factory(io_context, file_server);
		boost_rttp_server server(io_context, port, df_factory);

		cout << "listen on port " << port << endl;

		std::thread t(main_func, &io_context);

		while (server.server_ctx_.run) {
			/*if (server.server_ctx_.state[0] != 0)
				cout << server.server_ctx_.state << endl;*/
			this_thread::sleep_for(chrono::milliseconds(500));
		}

		t.join();
		file_server.stop();
		
	}
	catch (std::exception& e)
	{
		std::cerr << "Exception: " << e.what() << "\n";
	}

	return 0;
}
