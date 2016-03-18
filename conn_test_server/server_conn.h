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

typedef int nl_on_packet_recv(void *nlc, char *buf, size_t len); // ���ݵ����ʱ��

#define NL_CONN_OK 0 // ���������ݰ�
#define NL_CONN_ERROR_PACKET -1 // ��������ݰ�
#define NL_CONN_ERROR_EV_READ -2 // �����д�¼�
#define NL_CONN_ERROR_EV_WRITE -3 // �����д�¼�
#define NL_CONN_ERROR_SEVER_STOP -4 // ����ֹͣ
#define NL_CONN_ERROR_CONNECT_FAILED -5 // ����ʧ��

#define FLAG_LEN 4 // ���ձ�־
#define MAX_RECV_LEN 4097 // �����ճ���

// ����������
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
    int m_error_no; // �����

    unsigned int m_mask; // ����
    unsigned int m_block; // ����
    unsigned int *m_block_map; // ��ӳ��

    char m_recv_buf[MAX_RECV_LEN]; // ���ջ�����
    size_t m_recv_data_len; // �������ݳ���

    size_t m_max_send_len; // ���ķ��ͳ��ȣ���granularity
    size_t m_remain_send_len; // ʣ�෢�ͳ���

    unsigned int m_crc; // У��ֵ
    bool m_is_check; // �Ƿ�У��
	bool m_is_alter; // �Ƿ񽻻�
    int m_debuglevel;   //���Եȼ�
};
#endif
