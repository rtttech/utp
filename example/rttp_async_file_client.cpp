#include "utp_socket_c.h"
#include "os_common.h"
#include "http.h"

#include <iostream>
#include <deque>
#include <set>
#include <map>
#include <unordered_map>
#include <assert.h>
#include <string.h>
#include <random>
#include <time.h>
#include <memory>
#include <numeric>
#include <thread>
#include <mutex>
#include <strstream>

using namespace std;

struct rtsocket_client_context
{
	std::thread *thread_ptr = NULL;

	bool run = true;
	SOCKET socket = -1;
	
	RTSOCKET rttp_socket = 0;
	socket_io_info rttp_socket_io_info;

	std::deque<std::shared_ptr<udp_pkt_send_item>> udp_send_deq;
	std::deque<std::shared_ptr<udp_pkt_send_item>> udp_recv_deq;

	std::string remote_file;
	std::string local_file;

	std::string response_line;
	std::string remote_host;

	FILE* fp;
	uint64_t file_size = 0;
	uint64_t downloaded_size = 0;
	uint64_t write_pos = 0;
    
    time_t start_time = time(NULL);

	struct write_file_item
	{
		char *data = NULL;
		int size = 0;
	};

	std::deque<write_file_item> write_file_deq;
	std::mutex mxt;

	std::thread *write_file_thread = NULL;

	char state[4096] = { 0 };
};

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

int recv_response_line(RTSOCKET socket, socket_io_info& si)
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

inline void on_rtsocket_connect(RTSOCKET socket)
{
	cout << "\nsocket " << socket << " connected" << endl;

	rtsocket_client_context *ctx_ptr = (rtsocket_client_context*)rt_get_userdata(socket);

	char *req_head = new char[1024];
	std::strstream resp_stream(req_head, 1024);
	resp_stream << "GET " << ctx_ptr->remote_file << " HTTP/1.1\r\n";
	resp_stream << "Host: " << ctx_ptr->remote_host << "\r\n";
	resp_stream << "\r\n";
	
	ctx_ptr->rttp_socket_io_info.send_deq.push_back(std::shared_ptr<socket_send_item>(new socket_send_item(req_head, resp_stream.pcount())));

	rtsocket_send_data(socket, ctx_ptr->rttp_socket_io_info);
}

void thread_write_file_proc(rtsocket_client_context* ctx_ptr, std::string path_file)
{

	ctx_ptr->fp = fopen(path_file.c_str(), "wb");
	if (ctx_ptr->fp == NULL) {
		cout << "create file " << path_file << " failed"<<endl;
		ctx_ptr->run = false;
		return;
	}

	int deq_size = 0;
	while (true) {

		bool found_data = false;
		
		rtsocket_client_context::write_file_item item;
		ctx_ptr->mxt.lock();
		if (ctx_ptr->write_file_deq.size() > 0) {
			item = ctx_ptr->write_file_deq[0];
			ctx_ptr->write_file_deq.pop_front();
			found_data = true;
		}
		else {
			found_data = false;
		}
		ctx_ptr->mxt.unlock();

		if (found_data) {
			//cout << "write file, pos: " << ctx_ptr->write_pos << ",size: " << item.size<<endl;

			if(item.data == NULL && item.size == 0)
				break;

			fseek(ctx_ptr->fp, ctx_ptr->write_pos, SEEK_SET);
			size_t ret = fwrite(item.data, 1, item.size, ctx_ptr->fp);
			if (ret == item.size) {
				ctx_ptr->write_pos += ret;
			}
			else {
				cout << "write file error " << endl;
				ctx_ptr->run = false;
				return;
			}

			if (ctx_ptr->write_pos == ctx_ptr->file_size) {
				//cout << "\nfile download completed " << endl;
				ctx_ptr->run = false;
				return;
			}

			delete item.data;
		}
		else {
			this_thread::sleep_for(std::chrono::milliseconds(50));
		}
	}

	if (ctx_ptr->fp != NULL) {
		fclose(ctx_ptr->fp);
		ctx_ptr->fp = NULL;
	}
}

inline void on_rtsocket_read(RTSOCKET socket)
{
	rtsocket_client_context *ctx_ptr = (rtsocket_client_context*)rt_get_userdata(socket);
	socket_io_info &si = ctx_ptr->rttp_socket_io_info;

	while (true) {

		if (ctx_ptr->file_size == 0) {
			//recv response head
			if (ctx_ptr->rttp_socket_io_info.recv_buffer == NULL) {
				si.recv_buff_len = 4096;
				ctx_ptr->rttp_socket_io_info.recv_buffer = new char[si.recv_buff_len];
			}

			int ret = recv_response_line(socket, ctx_ptr->rttp_socket_io_info);
			if (ret > 0) {
				std::string line(si.recv_buffer, si.recv_buff_pos);
				ctx_ptr->response_line += line;
				si.recv_buff_pos = 0;

				if (line == "\n" || line == "\r\n") {
					HttpResponseHead resp;
					bool success = resp.Decode(ctx_ptr->response_line.c_str(), ctx_ptr->response_line.size());
					if (success && resp.GetStatusCode()/100 == 2 ) {
						delete ctx_ptr->rttp_socket_io_info.recv_buffer;
						ctx_ptr->rttp_socket_io_info.recv_buffer = NULL;
						ctx_ptr->file_size = resp.GetContentSumSize();
						ctx_ptr->write_file_thread = new std::thread(thread_write_file_proc, ctx_ptr, ctx_ptr->local_file);
					}
					else {
						cout << "error: " << ctx_ptr->response_line << endl;
						rt_close(ctx_ptr->rttp_socket);
						ctx_ptr->rttp_socket = 0;
						ctx_ptr->run = false;
						return;
					}
				}
				else {
					continue;
				}
			}
			else if (ret == -1) {
				return;
			}
			else {
				if (ret == 0) {
					cout << "connection closed by remote" << endl;
				}
				else {
					cout << "rt_recv return " << ret << endl;
				}
				rt_close(ctx_ptr->rttp_socket);
				ctx_ptr->rttp_socket = 0;
				ctx_ptr->run = false;
				return;
			}
		}
		else {
			if (si.recv_buffer == NULL) {
				si.recv_buff_len = 256*1024;
				si.recv_buff_pos = 0;
				si.recv_buffer = new char[si.recv_buff_len];
			}

			int ret = rt_recv(socket, si.recv_buffer + si.recv_buff_pos, si.recv_buff_len - si.recv_buff_pos, 0);
			if (ret > 0) {
				ctx_ptr->downloaded_size += ret;
				si.recv_buff_pos += ret;

				if (si.recv_buff_pos == si.recv_buff_len || ctx_ptr->downloaded_size == ctx_ptr->file_size) {
					//std::async(std::launch::async, thread_write_file, ctx_ptr->fp, ctx_ptr->write_pos, si.recv_buffer, si.recv_buff_pos);

					rtsocket_client_context::write_file_item wfi;
					wfi.data = si.recv_buffer;
					wfi.size = si.recv_buff_pos;

					ctx_ptr->mxt.lock();
					ctx_ptr->write_file_deq.push_back(wfi);
					ctx_ptr->mxt.unlock();

					si.recv_buffer = NULL;
					si.recv_buff_pos = 0;
					si.recv_buff_len = 0;
				}
			}
			else {
				if (ret == -1) {
					return;
				}
				else {
					if (ret == 0) {
						cout << "connection closed by remote" << endl;
					}
					else {
						cout << "rt_recv return " << ret << endl;
					}

					rtsocket_client_context::write_file_item wfi;

					ctx_ptr->mxt.lock();
					ctx_ptr->write_file_deq.push_back(wfi);
					ctx_ptr->mxt.unlock();

					rt_close(ctx_ptr->rttp_socket);
					ctx_ptr->rttp_socket = 0;
					ctx_ptr->run = false;

					return;
				}
			}
			
		}
		
	}
}


inline void on_rtsocket_write(RTSOCKET socket)
{
	rtsocket_client_context *ctx_ptr = (rtsocket_client_context*)rt_get_userdata(socket);
	socket_io_info &si = ctx_ptr->rttp_socket_io_info;
	rtsocket_send_data(socket, si);
}



inline void on_rtsocket_error(RTSOCKET socket)
{
	rtsocket_client_context *ctx_ptr = (rtsocket_client_context*)rt_get_userdata(socket);

	int errcode = rt_get_error(socket);
	cout << "\nrttp socket " << socket << " error: " << errcode << endl;
	rt_close(socket);
	ctx_ptr->rttp_socket = 0;
	ctx_ptr->run = false;
}

inline void on_rtsocket_event(RTSOCKET socket, int event)
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

inline void packet_send_imp(RTSOCKET socket, const char * data, int len, const char * sa, int sock_len)
{
	rtsocket_client_context *ctx_ptr = (rtsocket_client_context*)rt_get_userdata(socket);

	int64_t send_start = get_micro_second();
	int send_ret = ::sendto(ctx_ptr->socket, data, len, 0, (struct sockaddr *)sa, sock_len);
	int64_t send_end = get_micro_second();
	//cout << "udp send take " << send_end - send_start << endl;
	//cout << "send return " << send_ret;
	if (send_ret < 0) {
		std::shared_ptr<udp_pkt_send_item> ptr(new udp_pkt_send_item(data, len, (struct sockaddr *)sa, sock_len));
		ctx_ptr->udp_send_deq.push_back(ptr);
		//cout << "udp send quue size: " << ctx_ptr->udp_send_deq.size() << endl;
	}
}

inline void do_udp_send(rtsocket_client_context* ctx_ptr, SOCKET socket)
{
	while (ctx_ptr->udp_send_deq.size() > 0) {
		udp_pkt_send_item &si = *ctx_ptr->udp_send_deq[0];

		int  send_bytes = ::sendto(socket, si.buffer, si.len, 0, (struct sockaddr*)&si.addr, si.addr_len);
		if (send_bytes == si.len) {
			ctx_ptr->udp_send_deq.pop_front();
		}
		else {
			assert(send_bytes < 0);
			break;
		}
	}
}

inline void do_udp_recv(rtsocket_client_context* ctx_ptr, SOCKET socket)
{
	char buff[2000] = { 0 };

	int i = 0;
	while (i++ < 1000) {
		struct sockaddr_in sa;
		socklen_t from_len = sizeof(sa);
		memset(&sa, 0, from_len);

		//cout << "start recv: ";
		int64_t recv_start = get_micro_second();
		int bytes = ::recvfrom(socket, buff, sizeof(buff), 0, (struct sockaddr*)&sa, &from_len);
		int64_t recv_end = get_micro_second();

		//cout << " recv take " << recv_end - recv_start << endl;

		//cout << "udp recv return " << bytes << endl;
		if (bytes > 0) {
			int64_t handle_start = get_micro_second();
			//if (rand() % 3 != 0) //packet lost test
			{
				RTSOCKET s = rt_incoming_packet(buff, bytes, (const char*)&sa, from_len, ctx_ptr);
				int64_t handle_end = get_micro_second();
				//cout << bytes << " bytes "<<" handle packet take " << handle_end - handle_start << endl;
			}
		}
		else {
			return;
		}
	}
}


inline int rttp_client_main_func(rtsocket_client_context* ctx_ptr, const char* remote_addr, int port)
{
	init_socket();
    
	ctx_ptr->remote_host = remote_addr;

    int recv_buff_size = 4*1024*1024;
    
	ctx_ptr->socket = create_udp_socket(recv_buff_size);

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));

#if defined(SOCKADDR_WITH_LEN)
	sa.sin_len = sizeof(sa);
#endif


	sa.sin_family = AF_INET;
	std::string remote_ip = get_host_ip_address(remote_addr);
	if (remote_ip.size() == 0) {
		ctx_ptr->run = false;
		return 0;
	}
	else {
		//std::cout << "ip: " << remote_ip << std::endl;
	}

	sa.sin_addr.s_addr = inet_addr(remote_ip.c_str());
	sa.sin_port = htons(port);

	if (sa.sin_addr.s_addr == -1) {
		ctx_ptr->run = false;
		return 0;
	}

	uint64_t last_periodical_time = 0;
	uint64_t last_print_latency = 0;

	rt_set_callback(on_rtsocket_event, packet_send_imp);

	RTSOCKET client_rtsocket;

	client_rtsocket = rt_socket(RTSM_HIGH_THROUGHPUT);
    rt_setsockopt(client_rtsocket, RTSO_RCVBUF, &recv_buff_size, sizeof(recv_buff_size));
	rt_set_userdata(client_rtsocket, ctx_ptr);
	rt_connect(client_rtsocket, (const char*)&sa, sizeof(sa));

	while (ctx_ptr->run) {

		do_udp_send(ctx_ptr, ctx_ptr->socket);

		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(ctx_ptr->socket, &rfds);
		fd_set* read_fs_ptr = &rfds;

		fd_set* write_fs_ptr = NULL;
		fd_set wfds;
		FD_ZERO(&wfds);
		FD_SET(ctx_ptr->socket, &wfds);
		if (ctx_ptr->udp_send_deq.size() > 0) {
			write_fs_ptr = &wfds;
		}

		int waitms = 5;
		struct timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = waitms * 1000;
		int num = ::select(ctx_ptr->socket + 1, read_fs_ptr, write_fs_ptr, NULL, &tv);
		
		if (FD_ISSET(ctx_ptr->socket, read_fs_ptr)) {
			do_udp_recv(ctx_ptr, ctx_ptr->socket);
		}
		
		uint64_t cur_time = get_micro_second();
		if (cur_time - last_periodical_time >= 10000) {
			last_periodical_time = cur_time;
			rt_tick();
			int bytes = rt_state_desc(client_rtsocket, ctx_ptr->state, sizeof(ctx_ptr->state));
			if (bytes > 0 && bytes < sizeof(ctx_ptr->state)) {
				ctx_ptr->state[bytes] = 0;
			}
		}

	}

	rt_close(client_rtsocket);

	close_socket(ctx_ptr->socket);
	ctx_ptr->socket = -1;

	if (ctx_ptr->write_file_thread != NULL) {
		ctx_ptr->write_file_thread->join();
		delete ctx_ptr->write_file_thread;
		ctx_ptr->write_file_thread = NULL;
	}

	return 0;
}

void print_speed(rtsocket_client_context &ctx)
{
	if (ctx.file_size != 0) {
		int speed = 0;
		int time_elapsed = time(NULL) - ctx.start_time;
		if (time_elapsed > 0) {
			speed = ctx.downloaded_size / 1024 / time_elapsed;
		}
		cout << "\r(" << 100 * ctx.write_pos / ctx.file_size << "%)" << ctx.file_size << "/" << ctx.write_pos << "/" << speed << "KB/S     ";
		//cout<<ctx.state;
		cout << flush;
	}
}

int main(int argc, char* argv[])
{

	if (argc < 4) {
		cout << "usage: program <remote ip> <remote port> <remote file> [local file]" << endl;
		return 0;
	}

	rtsocket_client_context ctx;
	ctx.remote_file = argv[3];

	if (argc == 4) {
		ctx.local_file = ctx.remote_file[0] == '/' ? ctx.remote_file.substr(1) : ctx.remote_file;
	}
	else {
		ctx.local_file = argv[4];
	}

	std::thread t(rttp_client_main_func, &ctx, argv[1], atoi(argv[2]));

	while (ctx.run) {
		print_speed(ctx);
		this_thread::sleep_for(std::chrono::milliseconds(500));
	}
	print_speed(ctx);
	t.join();

	return 0;
}
