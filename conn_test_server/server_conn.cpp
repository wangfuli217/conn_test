#include "server_conn.h"
#include <assert.h>
#include "mt64.h"
#include "crc.h"

#ifdef WIN32
#include <winsock.h>
#include <stdint.h>
#else
#include<netinet/in.h>
#endif

#define MAX_PACKET_LEN (1024 * 1024) // 最大的包长度

server_conn::server_conn(int fd)
{
    m_fd = fd;

    m_error_no = NL_CONN_OK;

    m_recv_data_len = 0;

    m_mask = 0;
    m_block = 0;
    m_block_map = NULL;

    set_max_send_len(4096);

    m_crc = 0;

    m_is_check = false;
    m_is_alter = false;
    m_debuglevel = 0;
}

server_conn::~server_conn()
{
    if (m_block_map != NULL)
    {
        delete []m_block_map;
    }
}

int server_conn::get_socket()
{
    return m_fd;
}

struct event *server_conn::get_ev_read()
{
    return &m_ev_read;
}

struct event *server_conn::get_ev_write()
{
    return &m_ev_write;
}

int server_conn::recv_data(char *buf, size_t len)
{
    if (m_recv_data_len + len >= MAX_PACKET_LEN)
    {
        assert(false);
        return -1;  //关闭套接字
    }
    //这里有可能溢出
    memcpy(m_recv_buf + m_recv_data_len, buf, len);

    if (m_recv_data_len + len >= FLAG_LEN)
    {
        m_recv_data_len += len;
        m_recv_data_len -= FLAG_LEN;
        
        uint32_t * tmp = (uint32_t *)m_recv_buf; 
        unsigned int crc = (unsigned int)ntohl(*tmp);
//        printf("receive crc:%u, local crc:%u\n", crc, m_crc);
        if (m_is_check)
        {
            if (m_crc != crc)
            {
                fprintf(stderr, "check error. exit! receive crc:%u, local crc:%u\n", crc, m_crc);
                exit(-1);
            }
        }

        m_crc = 0;

        memmove(m_recv_buf, m_recv_buf + FLAG_LEN, m_recv_data_len);

        //关闭接收,发送数据
        //重新发送下一个过程
        event_add(get_ev_write(), NULL);
        event_del(get_ev_read());
        return 0;
    }
    else
    {
        //客户端发送的数据不够FLAG_LEN那么就不会继续发包
        m_recv_data_len += len;
    }
    return len;
}

size_t server_conn::get_recv_data_len()
{
    return m_recv_data_len;
}

int server_conn::on_send_data(char *buf, size_t send_len)
{
    if (m_is_check)
    {
        m_crc = cal_crc32(m_crc, buf, send_len);
	}
	else
	{
	    m_crc = 0;
	}

    if (m_remain_send_len < send_len)
    {
        m_remain_send_len = 0;
        return -1;
    }
    m_remain_send_len -= send_len;
    //一个过程以后才进行交互的
    if (m_remain_send_len == 0)
    {
        //如果交互模式就等待客户端回复，否则继续发下一轮
		if (m_is_alter)
		{
			//关闭发送,接收数据
			event_add(get_ev_read(), NULL);
			event_del(get_ev_write());
		}
        //下一轮
        m_remain_send_len = m_max_send_len;
        gen_block_map();
        return 0;
    }
    return m_remain_send_len;
}

void server_conn::set_max_send_len(size_t max_send_len)
{
    m_max_send_len = max_send_len;
    m_remain_send_len = max_send_len;
}

size_t server_conn::get_remain_data_len()
{
    return m_remain_send_len;
}

int server_conn::set_error_no(int error_no)
{
    return m_error_no = error_no;
}

int server_conn::get_error_no()
{
    return m_error_no;
}

void server_conn::set_mask(unsigned int mask)
{
    m_mask = mask;
}

int server_conn::get_mask()
{
    return m_mask;
}

unsigned int server_conn::get_off_map(unsigned int off)
{
    if (off >= m_max_send_len || m_block > m_max_send_len)
    {
        return 0;
    }

    unsigned int block_size = m_max_send_len / m_block;

    return m_block_map[off / block_size] + off % block_size;
}

void server_conn::gen_block_map()
{
    if (m_block < 1)
    {
        return;
    }

    for (int i = 0; i < (int)m_block + 1; i++)
    {
        m_block_map[i] = genrand64_int64() % (m_max_send_len - m_max_send_len / m_block);
    }
}

void server_conn::set_block(unsigned int block)
{
    if (block < 1)
    {
        return;
    }

    if (m_block != block)
    {
        if (m_block_map != NULL)
        {
            delete []m_block_map;
        }
        m_block_map = new unsigned int[block + 1];
    }
    m_block = block;
    gen_block_map();
}

int server_conn::get_block()
{
    return m_block;
}

void server_conn::set_check(bool check)
{
    m_is_check = check;
}

void server_conn::set_alter(bool alter)
{
	m_is_alter = alter;
}

int server_conn::set_debug_level(int debug_level)
{
    int tmp = m_debuglevel;
    m_debuglevel = debug_level;
    return tmp;
}
