#ifndef CLIENT_CONN_H
#define CLIENT_CONN_H

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

#include "time_spend.h"

#define NL_CONN_OK 0 // 正常的数据包
#define NL_CONN_ERROR_PACKET -1 // 错误的数据包
#define NL_CONN_ERROR_EV_READ -2 // 错误的写事件
#define NL_CONN_ERROR_EV_WRITE -3 // 错误的写事件
#define NL_CONN_ERROR_SEVER_STOP -4 // 服务停止
#define NL_CONN_ERROR_CONNECT_FAILED -5 // 连接失败

#define FLAG_LEN 4 // 接收标志
#define MAX_RECV_LEN 4097 // 最大接收长度

#define CLIENT_SEND_LEN 4

// 客户端连接类
class client_conn
{
public:
    client_conn(int fd);
    ~client_conn();
    int send_data();
    int get_socket();
    struct event *get_ev_read();
    struct event *get_ev_write();
    void set_max_recv_len(size_t max_recv_len);
//    size_t get_recv_data_len();

    int on_recv_data(char *buf, size_t recv_len);
//    void set_max_send_len(size_t max_send_len);
    size_t get_remain_data_len();
    int set_error_no(int error_no);
    int get_error_no();

    void set_repeat(unsigned int repeat);
    int get_repeat();
	void set_check(bool check);
	void set_alter(bool alter);

    void set_file(FILE *fp);
    void set_save_filename(char *szfilename);
    void set_slice_save(bool is_slice);
    int set_debug_level(int debug_level);
protected:
private:
    int m_fd; // socket
    int m_id;
    FILE *m_fp;
    static int s_id;
    struct event m_ev_read;
	struct event m_ev_write;
    int m_error_no; // 错误号

    unsigned int m_repeat;  //重复请求次数
    unsigned int m_repeat_count;    //已经请求的次数

    char m_send_buf[CLIENT_SEND_LEN]; // 发送缓存区
    size_t m_remain_send_len; // 缓冲区长度

    size_t m_max_recv_len; // 最大的接收长度
    long m_remain_recv_len; // 接收缓冲区长度

    time_spend m_ts; // 时间间隔计算
    unsigned int m_crc;
	bool m_is_check;
	bool m_is_alter; // 是否交互
    char m_date_out_filename[256]; // 保存接收的数据结果输出文件名
    FILE *m_date_fp;     // 保存接收的数据
    bool m_is_save_slice;   //分别保存每个数据包
    long long m_pkt_num;  //接收的数据包数量
    int     m_debug_level;  //调试输出等级
//    size_t m_max_send_len; // 最大的发送长度
};
#endif
