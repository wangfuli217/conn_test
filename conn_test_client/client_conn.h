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

#define NL_CONN_OK 0 // ���������ݰ�
#define NL_CONN_ERROR_PACKET -1 // ��������ݰ�
#define NL_CONN_ERROR_EV_READ -2 // �����д�¼�
#define NL_CONN_ERROR_EV_WRITE -3 // �����д�¼�
#define NL_CONN_ERROR_SEVER_STOP -4 // ����ֹͣ
#define NL_CONN_ERROR_CONNECT_FAILED -5 // ����ʧ��

#define FLAG_LEN 4 // ���ձ�־
#define MAX_RECV_LEN 4097 // �����ճ���

#define CLIENT_SEND_LEN 4

// �ͻ���������
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
    int m_error_no; // �����

    unsigned int m_repeat;  //�ظ��������
    unsigned int m_repeat_count;    //�Ѿ�����Ĵ���

    char m_send_buf[CLIENT_SEND_LEN]; // ���ͻ�����
    size_t m_remain_send_len; // ����������

    size_t m_max_recv_len; // ���Ľ��ճ���
    long m_remain_recv_len; // ���ջ���������

    time_spend m_ts; // ʱ��������
    unsigned int m_crc;
	bool m_is_check;
	bool m_is_alter; // �Ƿ񽻻�
    char m_date_out_filename[256]; // ������յ����ݽ������ļ���
    FILE *m_date_fp;     // ������յ�����
    bool m_is_save_slice;   //�ֱ𱣴�ÿ�����ݰ�
    long long m_pkt_num;  //���յ����ݰ�����
    int     m_debug_level;  //��������ȼ�
//    size_t m_max_send_len; // ���ķ��ͳ���
};
#endif
