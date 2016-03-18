#ifndef SERVER_CONN_H
#define SERVER_CONN_H

#include <sys/types.h>
#include <sys/stat.h>

#ifdef WIN32
#include <winsock2.h>
#include <mswsock.h>
#include <windows.h>
#endif

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <event.h>
#include <evutil.h>

typedef int nl_on_packet_recv(void *nlc, char *buf, size_t len); // 数据到达的时候

#define NL_CONN_OK 0 // 正常的数据包
#define NL_CONN_ERROR_PACKET -1 // 错误的数据包
#define NL_CONN_ERROR_EV_READ -2 // 错误的写事件
#define NL_CONN_ERROR_EV_WRITE -3 // 错误的写事件
#define NL_CONN_ERROR_SEVER_STOP -4 // 服务停止
#define NL_CONN_ERROR_CONNECT_FAILED -5 // 连接失败

#define FLAG_LEN 4 // 接收标志
#define MAX_RECV_LEN 4097 // 最大接收长度

// 服务连接类
class server_conn
{
public:
    server_conn(int fd);
    ~server_conn();
    int recv_data(char *buf, size_t len);
    int get_socket();
    struct event *get_ev_read();
    struct event *get_ev_write();
    size_t get_recv_data_len();

    int on_send_data(char *buf, size_t send_len);
    void set_max_send_len(size_t max_send_len);
    size_t get_remain_data_len();
    int set_error_no(int error_no);
    int get_error_no();

    void set_mask(unsigned int mask);
    int get_mask();
    void set_block(unsigned int block);
    int get_block();

    void set_check(bool check);
	void set_alter(bool alter);
    int set_debug_level(int debug_level);

    void gen_block_map();
    unsigned int get_off_map(unsigned int off);
protected:
private:
    int m_fd; // socket
    struct event m_ev_read;
	struct event m_ev_write;
    int m_error_no; // 错误号

    unsigned int m_mask; // 掩码
    unsigned int m_block; // 块数
    unsigned int *m_block_map; // 块映射

    char m_recv_buf[MAX_RECV_LEN]; // 接收缓存区
    size_t m_recv_data_len; // 接收数据长度

    size_t m_max_send_len; // 最大的发送长度，即granularity
    size_t m_remain_send_len; // 剩余发送长度

    unsigned int m_crc; // 校验值
    bool m_is_check; // 是否校验
	bool m_is_alter; // 是否交互
    int m_debuglevel;   //调试等级
};
#endif
