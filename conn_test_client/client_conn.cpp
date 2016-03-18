#include "client_conn.h"
#include <assert.h>
#include "crc.h"

#ifdef WIN32
#include <winsock.h>
#else
#include<netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#endif

int client_conn::s_id = 0;

client_conn::client_conn(int fd)
{
    m_fd = fd;

    m_error_no = NL_CONN_OK;

    m_repeat = 0;
    m_repeat_count = 0;

    memset(m_send_buf, 0, CLIENT_SEND_LEN);

    m_remain_send_len = CLIENT_SEND_LEN;

    set_max_recv_len(4096);

    m_id = s_id++;

    m_fp = NULL;

    m_crc = 0;
	
	m_is_check = false;

    memset(m_date_out_filename, 0, sizeof(m_date_out_filename));
    m_date_fp = NULL;
    m_is_save_slice = false;
    m_pkt_num = 0;
    m_debug_level = 0;
}

client_conn::~client_conn()
{
    //if (m_is_save_slice == false)
    //{
    //    //assert(m_date_fp == NULL);
    //    return;
    //}
    //else 
    {
        if (m_date_fp != NULL)
        {
            fclose(m_date_fp);
        }        
    }
}

int client_conn::get_socket()
{
    return m_fd;
}

struct event *client_conn::get_ev_read()
{
    return &m_ev_read;
}

struct event *client_conn::get_ev_write()
{
    return &m_ev_write;
}

int client_conn::send_data()
{
    int ret = send(m_fd, m_send_buf + CLIENT_SEND_LEN - m_remain_send_len, m_remain_send_len, 0);
    if (ret > 0)
    {
        m_remain_send_len -= ret;
        if (m_remain_send_len == 0)
        {
            //关闭发送,接收数据
            event_add(get_ev_read(), NULL);
            event_del(get_ev_write());
            m_remain_send_len = CLIENT_SEND_LEN;
            m_ts.reset();
        }
        else
        {
            event_add(get_ev_write(), NULL);
        }
    }

    return ret;
}

int client_conn::on_recv_data(char *buf, size_t recv_len)
{
    if (m_date_out_filename[0] != '\0')
    {
        if (m_is_save_slice == true)
        {
            char tmp_name[256] = {0};
            sprintf(tmp_name,"%s_S_r%d_p%lld",m_date_out_filename,m_repeat_count,m_pkt_num);
            FILE *slice_save_file = fopen(tmp_name, "wb");
            if (slice_save_file == NULL)
            {
                fprintf(stderr, "open %s failed!\n", m_date_out_filename);
            }
            else
            {
                if (fwrite(buf,1,recv_len,slice_save_file) != recv_len)
                {
                    int err = errno;
                    fprintf(stderr, "write slice %s error : %d info: %s\n",m_date_out_filename, err,strerror(err));
                }
                fclose(slice_save_file);
            }
        }
        //else
        {
            int write_len = recv_len;
            //接收的数据超过了期望的数据
            if (m_remain_recv_len <= recv_len )
            {                
                write_len = m_remain_recv_len;
                if (m_date_fp != NULL)
                {
                    //写入本过程剩余接收的
                    if (fwrite(buf,1,write_len,m_date_fp) != write_len)
                    {
                        int err = errno;
                        fprintf(stderr, "write %s error : %d info: %s\n",m_date_out_filename, err,strerror(err));
                    }
                    fclose(m_date_fp);
                    m_date_fp = NULL;
                    write_len = recv_len - m_remain_recv_len;
                    //打开下一个过程的文件写入
                    if (m_repeat_count + 1 < m_repeat && m_repeat != 0)
                    {
                        char tmpname[256] = {0};
                        sprintf(tmpname,"%s_r%d",m_date_out_filename,m_repeat_count + 1);
                        m_date_fp = fopen(tmpname, "wb");
                        if (m_date_fp == NULL)
                        {
                            fprintf(stderr, "open %s failed!\n", tmpname);
                        }
                        if (fwrite(buf + m_remain_recv_len,1,write_len,m_date_fp) != write_len)
                        {
                            int err = errno;
                            fprintf(stderr, "write next %s error : %d info: %s\n",m_date_out_filename, err,strerror(err));
                        }
                    }                    
                }

            }
            else if (m_date_fp != NULL)
            {
                if (fwrite(buf,1,recv_len,m_date_fp) != recv_len)
                {
                    int err = errno;
                    fprintf(stderr, "write normal %s error : %d info: %s\n",m_date_out_filename, err,strerror(err));
                }
            }
        }        
    }    
    //接收的数据包数量计数
    m_pkt_num++;    

    //非交互模式
	if (!m_is_alter)
	{
        //m_repeat_count += (m_remain_recv_len + recv_len) / m_max_recv_len;
		//m_remain_recv_len = (m_remain_recv_len + recv_len) % m_max_recv_len;
        m_remain_recv_len = m_remain_recv_len - recv_len;
        if (m_remain_recv_len <= 0)
        {
            if (m_remain_recv_len < 0)
            {
                if (m_debug_level > 0)
                {
                    fprintf(stderr, "recive more then expect! m_remain_recv_len %d,recv_len %d\n",m_remain_recv_len,recv_len);
                }                
            }
            m_repeat_count++;
            m_remain_recv_len += m_max_recv_len;    //下一次期望接收的大小
        }
        if (m_repeat_count >= m_repeat && m_repeat != 0)
        {
#ifdef WIN32
            printf("id:%d(%d), receive data: %I64d(%d)\n", m_id, m_fd, (__int64)m_max_recv_len * m_repeat, m_repeat);
#else
            printf("id:%d(%d), receive data: %lld(%d)\n", m_id, m_fd, (long long)m_max_recv_len * m_repeat, m_repeat);
#endif

            return -1;
        }
		return recv_len;
	}

    //校验数据包
    if (m_is_check)
    {
		m_crc = cal_crc32(m_crc, buf, recv_len); // 校验数据
	}
    //接收的数据必须和发送的数据一样大
    if (m_remain_recv_len < recv_len)
    {
        fprintf(stderr, "id:%d(%d), recv_len:%d, remain_recv_len:%d, (%d/%d)\n", m_id, m_fd, recv_len, m_remain_recv_len, m_repeat_count, m_repeat);
        assert(false);
        m_remain_recv_len = 0;
		exit(-1);
        return -1;
    }
    //一个过程中剩余的数据量
    m_remain_recv_len -= recv_len;
    if (m_remain_recv_len == 0)
    {
        unsigned int crc = htonl(m_crc);
        memcpy(m_send_buf, &crc, sizeof(unsigned int));
        m_crc = 0;
		
		//关闭接收,发送数据
        //接完一个过程以后校验数据
		event_add(get_ev_write(), NULL);
		event_del(get_ev_read());

        m_remain_recv_len = m_max_recv_len;
		
		if (m_fp != NULL)
		{
			fprintf(m_fp, "%d\t%d\t%f\n", m_id, m_repeat_count, m_ts.spend());
		}

        m_repeat_count++;
        if (m_repeat_count >= m_repeat && m_repeat != 0)
        {
#ifdef WIN32
            printf("id:%d(%d), receive data: %I64d(%d)\n", m_id, m_fd, (__int64)m_max_recv_len * m_repeat, m_repeat);
#else
            printf("id:%d(%d), receive data: %lld(%d)\n", m_id, m_fd, (long long)m_max_recv_len * m_repeat, m_repeat);
#endif

            return -1;
        }
        return 0;
    }
    return m_remain_recv_len;
}

void client_conn::set_max_recv_len(size_t max_recv_len)
{
    m_max_recv_len = max_recv_len;
    m_remain_recv_len = max_recv_len;
}

size_t client_conn::get_remain_data_len()
{
    return m_remain_send_len;
}

int client_conn::set_error_no(int error_no)
{
    return m_error_no = error_no;
}

int client_conn::get_error_no()
{
    return m_error_no;
}

void client_conn::set_repeat(unsigned int repeat)
{
    m_repeat = repeat;
}

int client_conn::get_repeat()
{
    return m_repeat;
}

void client_conn::set_file(FILE *fp)
{
    m_fp = fp;
}

void client_conn::set_check(bool check)
{
    m_is_check = check;
}

void client_conn::set_alter(bool alter)
{
	m_is_alter = alter;
}

void client_conn::set_save_filename(char *szfilename)
{
    sprintf(m_date_out_filename,"%s_id%d_fd%d",szfilename,m_id,m_fd);
    //if (m_is_save_slice == false)
    {
        char tmpname[256] = {0};
        sprintf(tmpname,"%s_r%d",m_date_out_filename,m_repeat_count);
        m_date_fp = fopen(tmpname, "wb");
        if (m_date_fp == NULL)
        {
            fprintf(stderr, "open %s failed!\n", tmpname);
        }
    }
}

void client_conn::set_slice_save(bool is_slice)
{
    m_is_save_slice = is_slice;
}

int client_conn::set_debug_level(int debug_level)
{
    int tmp = m_debug_level;
    m_debug_level = debug_level;
    return tmp;
}
