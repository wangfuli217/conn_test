#ifdef WIN32
#include <winsock2.h>
#include <mswsock.h>
#include <windows.h>
typedef int socklen_t;
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#endif

#ifdef _MSC_VER
#pragma warning(disable : 4786 4200 4103 4005 4018 4244 4146 4284 4503)
#endif

#include <signal.h>
#include <event.h>
#include <evutil.h>
#include <evhttp.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>

#include "client_conn.h"
#include "../conn_test_help.h"

#include <map>
using namespace std;

#ifdef WIN32
typedef int evutil_socket_t;
#endif

#ifndef EV_CONNECT
#define EV_CONNECT  0x20
#endif

#define GB (1024 * 1024 *1024)
#define MB (1024 * 1024)
#define KB (1024)

#define TMP_READ_BUF 8193 // 临时缓冲区

#define MAX_PATH_LEN 266 // 最大的名字长度
#define MAX_NAME_LEN 20 // 最大的名字长度

char g_ip_str[MAX_NAME_LEN] = "127.0.0.1"; // ip 地址
char g_bind_ip_str[MAX_NAME_LEN] = ""; // bind ip 地址
/* Port to listen on. */
unsigned int g_port = 5555; // 默认链接端口
unsigned int g_http_port = 0; // 默认http监听端口

char g_out_str[MAX_PATH_LEN] = "out.txt"; // 结果输出文件名
char g_date_out_str[MAX_PATH_LEN] = {0}; // 保存接收的数据结果输出文件名
FILE *g_fp = NULL;
FILE *g_date_fp = NULL;     // 保存接收的数据
bool g_is_slice = false;
int g_verbose = 0; //冗余输出

struct event_base *g_evbase = NULL; // 事件处理基础

map<int, client_conn *> g_conns; // socket与连接结构体的映射

int g_recv_buf_len = 1 * 1024 * 1024; // 接受缓冲区
int g_conn_count = 1; // 连接数
int g_repeat = 0; // 重复次数
int g_delay = 0; // 连接延迟
int g_tcp_recv_buf_len = -1; // 系统默认

int g_extreme = 0; // 极速模式
bool g_alter = false; // 交互模式
bool g_no_delay = false; // 禁用 Nagle 算法
int g_is_connecting_count = 0; // time_out是否关闭

int g_relay = 0; // 接力模式
int g_relay_count = 0; // 接力次数

int g_time_val = 1; // 显示速度的间隔时间
struct timeval g_last_show_time; // 上次显示时间
unsigned long long g_last_show_flow = 0; // 上次显示流量
unsigned long long g_new_flow = 0; // 最新流量
double g_flow_speed = 0.0; // 流速
char g_flow_speed_unit[3] = "B"; // 流速单位

int g_static_conn_count = 0; // 静态的连接计数

#ifdef WIN32
#include <string>
using namespace std;

string &replace_all_distinct(string &str, const string &old_value, const string &new_value) 
{ 
    for(string::size_type pos(0); pos != string::npos; pos += new_value.length())
    { 
        if((pos = str.find(old_value,pos)) != string::npos)
        {
            str.replace(pos, old_value.length(), new_value);
        }
        else
        {
            break;
        }
    } 
    return str;
}

void daemonize()
{
    string command_line = GetCommandLine();
    replace_all_distinct(command_line, "--silent", "");
    replace_all_distinct(command_line, "--n", "");
    replace_all_distinct(command_line, "-n", "");
    FreeConsole();
    WinExec(command_line.c_str(), SW_HIDE);
	exit(0);
}
#else
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>

void daemonize()
{
    pid_t pid = 0;
    struct rlimit rl;
    struct sigaction sa;
    
    /*
    * clear mask.
    */
    umask(0);
    
    /*
    * Get maximum number of file description.
    */
    if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
    {
        exit(-1);
    }
    
    /*
    * Become a session leader to lose controlling TTY.
    */
    if ((pid = fork()) < 0)
    {
        exit(-1);
    }
    else if (pid != 0) /* parent */
    {
        exit(0);
    }
    setsid();
    
    
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGHUP, &sa, NULL) < 0)
    {
        exit(-1);
    }
    if ((pid = fork()) < 0)
    {
        exit(-1);
    }
    else if (pid != 0)
    {
        exit(0);
    }
    
    if (chdir("/") < 0)
    {
        exit(-1);
    }
    
    if (rl.rlim_max == RLIM_INFINITY)
    {
        rl.rlim_max = 1024;
    }
    for (int i = 0; i < (int)rl.rlim_max; i++)
    {
        close(i);
    }
    int fd0, fd1, fd2;
    fd0 = open("/dev/null", O_RDWR);
    fd1 = dup(0);
    fd2 = dup(0);
}
#endif

static void timeout_show_cb(evutil_socket_t fd, short event, void *arg)
{
    struct timeval newtime, difference;
    struct event *timeout = (struct event *)arg;
    double elapsed;
    
    evutil_gettimeofday(&newtime, NULL);
    evutil_timersub(&newtime, &g_last_show_time, &difference);
    elapsed = difference.tv_sec +
        (difference.tv_usec / 1.0e6);

    if (g_new_flow - g_last_show_flow > GB)
    {
		g_flow_speed = (g_new_flow - g_last_show_flow) / elapsed / GB;
		strcpy(g_flow_speed_unit, "GB");
    }
    else if (g_new_flow - g_last_show_flow > MB)
    {
		g_flow_speed = (g_new_flow - g_last_show_flow) / elapsed / MB;
		strcpy(g_flow_speed_unit, "MB");
    }
    else if (g_new_flow - g_last_show_flow > KB)
    {
		g_flow_speed = (g_new_flow - g_last_show_flow) / elapsed / KB;
		strcpy(g_flow_speed_unit, "KB");
    }
    else
    {
		g_flow_speed = (g_new_flow - g_last_show_flow) / elapsed;
		strcpy(g_flow_speed_unit, "B");
    }
	
	printf("speed(%u):%f%s\n", (unsigned int)g_conns.size(), g_flow_speed, g_flow_speed_unit);

    g_last_show_time = newtime;
    g_last_show_flow = g_new_flow;

    if (g_conns.size() != 0 || g_is_connecting_count != 0)
    {
        struct timeval tv;
        evutil_timerclear(&tv);
        tv.tv_sec = g_time_val;
        event_add(timeout, &tv);
    }
}

unsigned int atobyte(const char *str)
{
    int i = 0;
    size_t len = strlen(str);
    char *tmp = (char *)malloc(len + 1);
    if (tmp == NULL)
    {
        return 0;
    }

    unsigned mul = 1;
    strcpy(tmp, str);
    for (i = 0; i < (int)len; i++)
    {
         if (tmp[i] < '0' || tmp[i] > '9')
         {
            switch (tmp[i])
            {
            case 'b':
            case 'B':
                mul = 1;
                break;
            case 'k':
            case 'K':
                mul = 1024;
                break;
            case 'm':
            case 'M':
                mul = 1024 * 1024;
                break;
            case 'g':
            case 'G':
                mul = 1024 * 1024 * 1024;
                break;
            default:
                mul = 0;
            break;
            }
            tmp[i] = '\0';
            break;
         }
    }

    int base = atoi(tmp);

    free(tmp);

    return (unsigned int)base * mul;
}

char *get_error_string(int no)
{
#ifdef WIN32
    LPSTR lpBuffer;    
    FormatMessage ( FORMAT_MESSAGE_ALLOCATE_BUFFER  |
        FORMAT_MESSAGE_IGNORE_INSERTS  |
        FORMAT_MESSAGE_FROM_SYSTEM,
        NULL,
        no, // 此乃错误代码，通常在程序中可由 GetLastError()得之
        LANG_NEUTRAL,
        (LPTSTR) & lpBuffer,
        0 ,
         NULL );
    return lpBuffer;
#else
    return strerror(no);
#endif
}

static int is_try_again()
{
#ifdef WIN32
    return WSAEWOULDBLOCK == WSAGetLastError();
#else
    return EAGAIN == errno || EINTR == errno;
#endif
}

static int is_try_again_connect()
{
#ifdef WIN32
    return WSAEWOULDBLOCK == WSAGetLastError();
#else
    return EINPROGRESS == errno;
#endif
} 

static void msleep(unsigned int ms)
{
#ifdef WIN32
    Sleep(ms);
#else
    usleep(1000 * ms);
#endif
}

static void on_read(evutil_socket_t fd, short ev, void *arg);
static void on_write(evutil_socket_t fd, short ev, void *arg);
static void on_connect(evutil_socket_t fd, short ev, void *arg);
static void close_client(int fd);

int add_conn()
{
    struct sockaddr_in conn_addr;
    
    memset(&conn_addr, 0, sizeof(conn_addr));
    conn_addr.sin_family = AF_INET;
    conn_addr.sin_addr.s_addr = inet_addr(g_ip_str);
    conn_addr.sin_port = htons(g_port);
    //TCP协议
    evutil_socket_t conn_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (conn_fd < 0)
    {
        fprintf(stderr, "socket failed.\n");
        return -1;
    }
    
    /* Set the socket to non-blocking, this is essential in event
    * based programming with libevent. */
    if (evutil_make_socket_nonblocking(conn_fd) < 0)
    {
        fprintf(stderr, "failed to set client socket to non-blocking");
    }

	if (strlen(g_bind_ip_str) > 0)
	{
		struct sockaddr_in client_addr;
		memset(&client_addr, 0, sizeof(client_addr));
		client_addr.sin_family = AF_INET;
		client_addr.sin_addr.s_addr = inet_addr(g_bind_ip_str);
		client_addr.sin_port = htons(0);
		
		if (bind(conn_fd, (struct sockaddr *)&client_addr,
			sizeof(client_addr)) < 0)
		{
			fprintf(stderr, "bind failed. errno:%d, info:%s\n", EVUTIL_SOCKET_ERROR(), get_error_string(EVUTIL_SOCKET_ERROR()));
			return 0;
		}
	}
	
    if (g_relay > 0)
    {
        g_relay_count++;
    }

    int ret = connect(conn_fd, (struct sockaddr *)&conn_addr, sizeof(struct sockaddr_in));
    int err = EVUTIL_SOCKET_ERROR();
    client_conn *nlc = new client_conn(conn_fd);
    
    event_set(nlc->get_ev_read(), conn_fd, EV_READ | EV_PERSIST, on_read, nlc);
    
    if (ret == 0)
    {
        event_set(nlc->get_ev_write(), conn_fd, EV_WRITE, on_write, nlc);
        event_add(nlc->get_ev_write(), NULL);
		
		g_is_connecting_count++;
    }
    else if(is_try_again_connect())
    {
        event_set(nlc->get_ev_write(), conn_fd, EV_CONNECT | EV_WRITE, on_connect, nlc);
        event_add(nlc->get_ev_write(), NULL);
		
		g_is_connecting_count++;
        //fprintf(stderr, "connect retry, ret %d, errno %d info:%s\n", ret, err,get_error_string(err));
    }
    else
    {
        nlc->set_error_no(NL_CONN_ERROR_CONNECT_FAILED);
        close_client(conn_fd);
        fprintf(stderr, "connect failed, ret %d, errno %d\n", ret, errno);
    }

    printf("current connected sockets number:%u\n", (unsigned int)g_conns.size());

    return 0;
}

static void close_client(int fd)
{
    map<int, client_conn *>::iterator it = g_conns.find(fd);
    if (it != g_conns.end())
    {
        printf("connection close.(%d)\n", fd);
        event_del(it->second->get_ev_read());
        event_del(it->second->get_ev_write());
        delete it->second;
        EVUTIL_CLOSESOCKET(fd);
        g_conns.erase(it);

        if (g_relay > 0)
        {
            if (g_relay_count < g_conn_count * g_relay)
            {
                add_conn();
                printf("connection %d start.\n", g_relay_count);
                if ((g_delay == 0 && (g_static_conn_count++ % 10 == 0)) ||
                    g_delay != 0)
                {
                    msleep(g_delay);
                }
            }
        }
    }
    printf("current connected sockets number:%u\n", (unsigned int)g_conns.size());
}

/**
 * This function will be called by libevent when the client socket is
 * ready for reading.
 */
static void on_read(evutil_socket_t fd, short ev, void *arg)
{
    client_conn *nlc = (client_conn *)arg;
	int len;

    char buf[TMP_READ_BUF];

	len = recv(fd, buf, TMP_READ_BUF - 1, 0);
	if (len == 0)
    {
		close_client(fd);
		return;
	}
	else if (len < 0 && (!is_try_again())) 
    {
        fprintf(stderr, "recv(%d) failed. len:%d, errno:%d, info:%s\n", 
            fd, len, EVUTIL_SOCKET_ERROR(), get_error_string(EVUTIL_SOCKET_ERROR()));
        close_client(fd);
        return;
	}

	if(len > 0)
    {
        g_new_flow += len;

        int ret = nlc->on_recv_data(buf, len);
        if (ret == 0)
        {
			/*
			if (!g_alter)
			{
				if (event_add(nlc->get_ev_read(), NULL) != 0)
				{
					nlc->set_error_no(NL_CONN_ERROR_EV_READ);
					close_client(fd);
				}
			}
			*/
			if (g_alter)
			{
				if (event_del(nlc->get_ev_read()) != 0)
				{
					nlc->set_error_no(NL_CONN_ERROR_EV_READ);
					close_client(fd);
				}
			}
            return;
        }

        if (ret < 0)
        {
            printf("end socket\n");
            close_client(fd);
            return;
        }
        //ret >0 正常接收
        if (nlc->get_error_no() < 0)
        {
            close_client(fd);
            return;
        }
    }
	/*
    if (event_add(nlc->get_ev_read(), NULL) != 0)
    {
        nlc->set_error_no(NL_CONN_ERROR_EV_READ);
        close_client(fd);
    }
	*/
}

/**
 * This function will be called by libevent when the client socket is
 * ready for writing.
 */
static void on_write(evutil_socket_t fd, short ev, void *arg)
{
	client_conn *nlc = (client_conn *)arg;

    int len = nlc->send_data();
	if (len == 0)
    {
		close_client(fd);
		return;
	}
	else if (len < 0 && (!is_try_again()))
    {
        fprintf(stderr, "send(%d) failed. len:%d, errno:%d, info:%s\n", 
            fd, len, EVUTIL_SOCKET_ERROR(), get_error_string(EVUTIL_SOCKET_ERROR()));
		close_client(fd);
		return;
	}
}

/**
 * This function will be called by libevent when there is a connection
 * ready to be connected.
 */
static void on_connect(evutil_socket_t fd, short ev, void *arg)
{
	client_conn *nlc = (client_conn *)arg;

	g_is_connecting_count--;
	
	if (ev != 0)
    {
        socklen_t len = sizeof(int);
        int error = 0;
        getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&error, &len);
        if (error == 0)
        {
            printf("connect ok. fd:%d\n", fd);
        }
        else
        {
            fprintf(stderr, "connect(%d) failed. socket errno:%d, info:%s\n\tcommon error:%d info:%s\n", 
                fd, EVUTIL_SOCKET_ERROR(), get_error_string(EVUTIL_SOCKET_ERROR()),error,get_error_string(error));
            nlc->set_error_no(NL_CONN_ERROR_EV_WRITE);
		    close_client(fd);

            return;
        }
/*
		int error = 0;
        socklen_t len;
        getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&error, &len);

        if (error == 0)
        {
            printf("connect ok. fd:%d\n", fd);
        }
        else
        {
            fprintf(stderr, "connect(%d) failed. errno:%d, info:%s\n",
                fd, EVUTIL_SOCKET_ERROR(), get_error_string(EVUTIL_SOCKET_ERROR()));
		    close_client(fd);
			return;
        }
*/
        if (g_tcp_recv_buf_len >= 0)
        {
            setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char*)&g_tcp_recv_buf_len, sizeof(int));
        }

		if (g_no_delay)
		{
			int flag;
			setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag));
		}

        g_conns.insert(pair<int, client_conn *>(fd, nlc));
        nlc->set_debug_level(g_verbose);
        nlc->set_max_recv_len(g_recv_buf_len);
        nlc->set_repeat(g_repeat);
        nlc->set_file(g_fp);
		nlc->set_alter(g_alter);
        //slice需要在前面
        if (g_is_slice == true)
        {
            nlc->set_slice_save(true);
        }
        if (strlen(g_date_out_str) != 0)
        {
            nlc->set_save_filename(g_date_out_str);
        }      
		
		if (g_extreme == 0)
		{
		    nlc->set_check(true);
		}

		event_set(nlc->get_ev_write(), fd, EV_WRITE, on_write, nlc);
	
		if(event_add(nlc->get_ev_write(), NULL) != 0)
        {
            nlc->set_error_no(NL_CONN_ERROR_EV_WRITE);
			close_client(fd);
		}
	} 
    else
    {
        fprintf(stderr, "connect(%d) failed. errno:%d, info:%s\n", 
             fd, EVUTIL_SOCKET_ERROR(), get_error_string(EVUTIL_SOCKET_ERROR()));
        nlc->set_error_no(NL_CONN_ERROR_EV_WRITE);
		close_client(fd);
    }
}

void print_usage(bool detail = false)
{
    fprintf(stderr, "usage: conn_test_client -[hvipjgcrodbltxaqnyOsVH] [options]\n");
    fprintf(stderr, "\t-h --help\n");
    fprintf(stderr, "\t-H --detailhelp      详细帮助\n");
    fprintf(stderr, "\t-v --version         版本\n");
    fprintf(stderr, "\t-i --ip              指定对端IP\n");
    fprintf(stderr, "\t-p --port            指定对端端口\n");
	fprintf(stderr, "\t-j --bind            绑定本端IP\n");
    fprintf(stderr, "\t-g --granularity     一个过程接收的数据量\n");
    fprintf(stderr, "\t-c --count           连接数\n");
    fprintf(stderr, "\t-r --repeat          重复的过程次数\n");
    fprintf(stderr, "\t-o --out\n");    
    fprintf(stderr, "\t-d --delay           建立连接延时\n");
    fprintf(stderr, "\t-b --buffer          缓冲区大小\n");
    fprintf(stderr, "\t-l --relay           接力模式\n");
    fprintf(stderr, "\t-t --time            回显间隔\n");
	fprintf(stderr, "\t-a --alternative     交互模式\n");
	fprintf(stderr, "\t-q --nodelay         禁用Nagle算法\n");
	fprintf(stderr, "\t-n --silent\n");
	fprintf(stderr, "\t-y --http\n");
    fprintf(stderr, "\t-O --dateoutput      保存接收的数据文件名\n");
    fprintf(stderr, "\t-s --slice           分片保存而不是全部存到一个文件内\n");
    fprintf(stderr, "\t-V --verbose         显示调试输出\n");
	
#ifdef _MSC_VER
    fprintf(stderr, "build: compiler = msc %d, date = %s\n\n", _MSC_VER, __DATE__);
#else
    fprintf(stderr, "build: compiler = gcc %s, date = %s\n\n", __VERSION__, __DATE__);
#endif // _MSC_VER

	if (detail == true)
	{
        fprintf(stderr, "\n帮助手册：\n\n");
        fprintf(stderr, "%s\n", conn_help);
	}	
}

int parse_parameters(int argc, char **argv)
{
    const struct option long_options[] =
    {
        {"help",    0, NULL, 'h'},
        {"version", 0, NULL, 'v'},
        {"ip",      1, NULL, 'i'},
        {"port",    1, NULL, 'p'},
        {"bind",    1, NULL, 'j'},
        {"granularity",      1, NULL, 'g'},
        {"count",   1, NULL, 'c'},
        {"repeat",  1, NULL, 'r'},
        {"out",     1, NULL, 'o'},
        {"delay",   1, NULL, 'd'},
        {"buffer",  1, NULL, 'b'},
        {"relay",   1, NULL, 'l'},
        {"time",    1, NULL, 't'},
        {"extreme", 0, NULL, 'x'},
        {"alternative",      0, NULL, 'a'},
        {"nodelay", 0, NULL, 'q'},
        {"silent",  0, NULL, 'n'},
		{"http",    1, NULL, 'y'},
        {"dateoutput",    1, NULL, 'O'},
        {"slice",    0, NULL, 's'},
        {"verbose", 1, NULL, 'V'},
        {"detailhelp",    0, NULL, 'H'},
        {NULL,      0, NULL,   0}
    };

    const char* const short_options = "hvi:p:j:g:c:r:o:d:b:l:t:xaqny:O:sV:H";

    int ch = 0;

    while ((ch = getopt_long(argc, argv, short_options, long_options, NULL)) != -1)
    {
        switch (ch)
        {
        case 'h':   //帮助
            print_usage();
            return 0;
            break;
        case 'v':   //version
            printf("conn_test_client 8.0 [%s] by yinwei\n", __DATE__);
            return 0;
            break;
        case 'i':   //对端IP
            strncpy(g_ip_str, optarg, MAX_NAME_LEN);
            break;
        case 'p':   //端口
            g_port = atoi(optarg);
            if (g_port == 0)
            {
                fprintf(stderr, "port error.\n");
                return -1;
            }
            break;
        case 'j':   //本端IP
            strncpy(g_bind_ip_str, optarg, MAX_NAME_LEN);
            break;
        case 'g':   //粒度，即发送数据的大小
            g_recv_buf_len = atobyte(optarg);
            if (g_recv_buf_len <= 0)
            {
                fprintf(stderr, "granularity error.\n");
                return -1;
            }
            break;
        case 'c':   //连接线程数
            g_conn_count = atoi(optarg);
            if (g_conn_count <= 0)
            {
                fprintf(stderr, "count error.\n");
                return -1;
            }
            break;
        case 'r':   //重复请求次数 
            g_repeat = atoi(optarg);
            if (g_repeat < 0)
            {
                fprintf(stderr, "repeat error.\n");
                return -1;
            }
            break;
        case 'o':
            strncpy(g_out_str, optarg, MAX_PATH_LEN);
            break;        
        case 'd':
            g_delay = atoi(optarg);
            if (g_delay <= 0)
            {
                fprintf(stderr, "delay error.\n");
                return -1;
            }
            break;
        case 'b':
            g_tcp_recv_buf_len = atoi(optarg);
            if (g_tcp_recv_buf_len < 0)
            {
                fprintf(stderr, "buffer error.\n");
                return -1;
            }
            g_tcp_recv_buf_len *= 1024;
            break;
        case 'l':
            g_relay = atoi(optarg);
            if (g_relay <= 0)
            {
                fprintf(stderr, "relay error.\n");
                return -1;
            }
            break;
        case 't':
            g_time_val = atoi(optarg);
            if (g_time_val < 0)
            {
                fprintf(stderr, "time error.\n");
                return -1;
            }
            break;
        case 'x':
            g_extreme = 1;
            break;
        case 'a':
            g_alter = true;
            break;
        case 'q':
            g_no_delay = true;
            break;
        case 'n':
            daemonize();
            break;
		case 'y':
		    g_http_port = atoi(optarg);
            if (g_http_port <= 0)
            {
                fprintf(stderr, "http port error.\n");
                return -1;
            }
            break;
        case 'O':
            strncpy(g_date_out_str, optarg, MAX_PATH_LEN);
            break;
        case 's':
            g_is_slice = true;
            break;
        case 'V':
            g_verbose = atoi(optarg);
            break;
        case 'H':   //帮助
            print_usage(true);
            return 0;
            break;
        default:
            break;
        }
    }
    
    if (!g_alter)
    {
        g_extreme = 1;
    }
    return 1;
}

void generic_request_handler(struct evhttp_request *req, void *arg)
{
    struct evbuffer *returnbuffer = evbuffer_new();
	evhttp_add_header(req->output_headers, "Content-Type", "text/html; charset=UTF-8");
    evhttp_add_header(req->output_headers, "Server", "conn_test_client");
    evhttp_add_header(req->output_headers, "Connection", "close");
	
	evbuffer_add_printf(returnbuffer, "<html><head><title>conn_test_client</title>");

	if (g_time_val > 0)
	{
		evbuffer_add_printf(returnbuffer, "<meta http-equiv=\"refresh\" content=\"%d\"/>", g_time_val);
	}

	evbuffer_add_printf(returnbuffer, "</head><body>");

	evbuffer_add_printf(returnbuffer, "<font size=\"24px\">");
	evbuffer_add_printf(returnbuffer, "<table align=\"center\">");
	evbuffer_add_printf(returnbuffer, "<tr><td><font size=\"24px\">Connections:</font></td><td><strong><font color=\"blue\" size=\"24px\">%u</font></strong></td></tr>", (unsigned int)g_conns.size());
#ifndef WIN32
	evbuffer_add_printf(returnbuffer, "<tr><td><font size=\"24px\">Total Flow:</font></td><td><strong><font color=\"blue\" size=\"24px\">%lluB</font></strong></td></tr>", g_new_flow);
#else
	evbuffer_add_printf(returnbuffer, "<tr><td><font size=\"24px\">Total Flow:</font></td><td><strong><font color=\"blue\" size=\"24px\">%I64uB</font></strong></td></tr>", g_new_flow);
#endif
	evbuffer_add_printf(returnbuffer, "<tr><td><font size=\"24px\">Total Speed:</font></td><td><strong><font color=\"blue\" size=\"24px\">%f%s</font></strong></td></tr>", g_flow_speed, g_flow_speed_unit);
	evbuffer_add_printf(returnbuffer, "</table>");
	evbuffer_add_printf(returnbuffer, "</font>");
    evbuffer_add_printf(returnbuffer, "</body></html>");
    evhttp_send_reply(req, HTTP_OK, "Client", returnbuffer);
    evbuffer_free(returnbuffer);
    return;
}

void exit_handler(int sig)
{
	event_base_loopexit(g_evbase, NULL);
}

int main(int argc, char **argv)
{
    int ret = 0;
    if ((ret = parse_parameters(argc, argv)) <= 0)
    {
        return ret;
    }

#ifdef WIN32
	WSADATA wsaData;

	int err = WSAStartup( MAKEWORD( 2, 0 ), &wsaData );
	if ( err != 0 )
    {
		fprintf(stderr, "couldn't find a usable winsock.dll.\n" );
		return -1;
	}
#else
	signal(SIGPIPE, SIG_IGN);
#endif

	signal(SIGTERM, exit_handler);
	signal(SIGINT, exit_handler);

	if (g_alter)
	{
		g_fp = fopen(g_out_str, "w");
		if (g_fp == NULL)
		{
			fprintf(stderr, "open %s failed\n", g_out_str);
		}
	}

    /* Initialize libevent. */
    g_evbase = event_init();
    printf("event method:%s.\n", event_base_get_method(g_evbase));

    for (int i = 0; i < g_conn_count; i++)
    {
        add_conn();
        printf("connection %d start.\n", i);
        if ((g_delay == 0 && g_static_conn_count++ % 10 == 0) ||
            g_delay != 0)
        {
            msleep(g_delay);
        }
    }

	struct event timeout;

    if (g_time_val > 0)
    {
        struct timeval tv;
        int flags = 0;

        /* Initalize one event */
        event_assign(&timeout, g_evbase, -1, flags, timeout_show_cb, (void*) &timeout);
        //evtimer_set(&timeout, timeout_cb, &timeout);

        evutil_timerclear(&tv);
        tv.tv_sec = g_time_val;
        event_add(&timeout, &tv);
        
        evutil_gettimeofday(&g_last_show_time, NULL);
    }
	
	if (g_http_port > 0)
	{
		const char *http_addr = "0.0.0.0";
		struct evhttp *http_server = NULL;
		http_server = evhttp_start(http_addr, g_http_port);
		if (http_server == NULL)
		{   
			fprintf(stderr, "Http server cann't start!\n");
		}
		else
		{
			evhttp_set_gencb(http_server, generic_request_handler, NULL);
		}
	}

    /* Start the libevent event loop. */
    event_dispatch();

    while (!g_conns.empty())
    {
        map <int, client_conn *>::iterator it = g_conns.begin();
        it->second->set_error_no(NL_CONN_ERROR_SEVER_STOP);
        close_client(it->first);
    }
	
    if (g_fp != NULL)
    {
        fclose(g_fp);
    }
	
#ifdef WIN32
	WSACleanup();
#endif

	return 0;
}
