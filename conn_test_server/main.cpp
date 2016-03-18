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
#include <sys/wait.h>
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

#include "server_conn.h"
#include "mt64.h"
#include "mt32.h"
#include "../conn_test_help.h"

#include <map>
#include <deque>
using namespace std;

#ifdef WIN32
typedef int evutil_socket_t;
#endif

#define GB (1024 * 1024 *1024)
#define MB (1024 * 1024)
#define KB (1024)

#define TMP_READ_BUF 4097 // 临时缓冲区

#define R_REDUNDANCY 0 // 冗余模式
#define R_RANDOM 1 // 随机模式
#define R_ZERO 2 // 全0模式
#define R_REDUNDANCY_CHAOS 3 // 冗余混乱模式
#define R_REDUNDANCY_NO_XOR 4    //冗余不加密
#define R_REDUNDANCY_CHAOS_NO_XOR 5 // 冗余混乱不加密模式，这个模式约等于随机
#define R_FILE  6                   //文件模式，TCP协议发送文件

#define RANDOM_32 0
#define RANDOM_64 1
#define MAX_PROCESS_NUM 64 // 最大子进程数

#define MAX_NAME_LEN 20 // 最大的名字长度
char g_bind_ip_str[MAX_NAME_LEN] = ""; // bind ip 地址

unsigned int g_port = 5555; // 监听端口
unsigned int g_http_port = 0; // 默认http监听端口

struct event_base *g_evbase = NULL;

map<int, server_conn *> g_conns; // socket与连接结构体的映射
deque<int> g_send_conn_deque; // 流控等待队列

int g_send_buf_len = 1 * 1024 * 1024;   //默认1M
int g_max_send_len = 4096; // 最大发送长度
int g_duplicate_len = 0; // 默认按照重复数据块数  //把生成的随机数据冗余granularity/duplicate份以扩充到granularity大小,只在没有指定文件时生效。
int g_block = 0; // 块大小
char *g_send_buf = NULL;
int g_seed = 0; // 随机化种子
int g_random = R_RANDOM;
int g_scope = RANDOM_64; // 默认采用64位的随机函数
int g_tcp_send_buf_len = -1; // 系统默认
char g_in_file_name[TMP_READ_BUF];
bool g_check = false; // 校验
bool g_same = false; // 相同模式
bool g_alter = false; // 交互模式
bool g_no_delay = false; // 禁用 Nagle 算法
int g_verbose = 0; //冗余输出

struct timeval g_last_time; // 上次时间
unsigned long long g_last_flow = 0; // 上次流量
unsigned long long g_last_show_flow = 0; // 上次显示流量
struct timeval g_last_show_time; // 上次时间
unsigned long long g_new_flow = 0; // 最新流量
double g_flow_speed = 0.0; // 流速
char g_flow_speed_unit[3] = "B"; // 流速单位

double g_limit_flow = 0.0; // 流控限速大小
int g_process_number = 0; // 子进程数

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

pid_t g_child_pid[MAX_PROCESS_NUM]; // 子进程id

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

void gen_random_buf(char *buf, int len)
{
    unsigned long long tmp_random = 0;
    unsigned long tmp_random32 = 0;
    int i = 0;
//	int count = 0;

    if (g_scope == RANDOM_64)
    {
        for (i = 0; i < len / (int)sizeof(unsigned long long); i++)
        {
            tmp_random = genrand64_int64();
            memcpy(g_send_buf + i * sizeof(unsigned long long), &tmp_random, sizeof(unsigned long long));
        }
        
        tmp_random = genrand64_int64();
        memcpy(buf + i * sizeof(unsigned long long), &tmp_random, len % sizeof(unsigned long long));
    }
	else if (g_scope == RANDOM_32)
	{
        for (i = 0; i < len / (int)sizeof(unsigned long); i++)
        {
            tmp_random32 = genrand_int32();
            memcpy(g_send_buf + i * sizeof(unsigned long), &tmp_random32, sizeof(unsigned long));
        }
        
        tmp_random32 = genrand_int32();
        memcpy(buf + i * sizeof(unsigned long), &tmp_random32, len % sizeof(unsigned long));
	}
}

static int is_try_again()
{
#ifdef WIN32
    return WSAEWOULDBLOCK == WSAGetLastError();
#else
    return EAGAIN == errno || EINTR == errno;
#endif
} 

int g_count = 0; // 流量更新间隔，大致100ms一次

static void timeout_cb(evutil_socket_t fd, short event, void *arg)
{
    struct timeval newtime;
    struct event *timeout = (struct event *)arg;
    
    evutil_gettimeofday(&newtime, NULL);

    if (g_count % 10 == 0)
    {
        g_last_time = newtime;
        g_last_flow = g_new_flow;
    }

    g_count++;

    int deque_len = g_send_conn_deque.size();
    int count = 0;
    while (count <= deque_len / 100)
    {
        if (!g_send_conn_deque.empty())
        {
            int fd = *(g_send_conn_deque.begin());

            map<int, server_conn *>::iterator it = g_conns.find(fd);
            if (it != g_conns.end())
            {
                server_conn *nlc = it->second;
                event_add(nlc->get_ev_write(), NULL);
            }
            g_send_conn_deque.pop_front();
        }
        count++;
    }

    struct timeval tv;
    evutil_timerclear(&tv);
    tv.tv_sec = 0;
    tv.tv_usec = 10000;
    event_add(timeout, &tv);
}

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

    g_last_show_time = newtime;
    g_last_show_flow = g_new_flow;

    struct timeval tv;
    evutil_timerclear(&tv);
    tv.tv_sec = 1;
    event_add(timeout, &tv);
}

static void close_client(int fd)
{
    map<int, server_conn *>::iterator it = g_conns.find(fd);
    if (it != g_conns.end())
    {
        printf("connection close.(%d)\n", fd);
        event_del(it->second->get_ev_read());
        event_del(it->second->get_ev_write());
        delete it->second;
        EVUTIL_CLOSESOCKET(fd);
        g_conns.erase(it);
    }

    printf("current connected sockets number:%u\n", (unsigned int)g_conns.size());
}

/**
 * This function will be called by libevent when the client socket is
 * ready for reading.
 */
static void on_read(evutil_socket_t fd, short ev, void *arg)
{
    server_conn *nlc = (server_conn *)arg;
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
        int ret = nlc->recv_data(buf, len);
        
        if (nlc->get_error_no() < 0)
        {
            close_client(fd);
            return;
        }
        
        if (ret == 0)
        {
            return;
        }

        if (ret < 0)
        {
            close_client(fd);
            return;
        }
    }
    
    if (event_add(nlc->get_ev_read(), NULL) != 0)
    {
        nlc->set_error_no(NL_CONN_ERROR_EV_READ);
        close_client(fd);
    }
}

/**
 * This function will be called by libevent when the client socket is
 * ready for writing.
 */
static void on_write(evutil_socket_t fd, short ev, void *arg)
{
	server_conn *nlc = (server_conn *)arg;
    char *send_buf = NULL;
    //流控
    if (g_limit_flow > 0.0)
    {
        struct timeval newtime, difference;
        double elapsed;
    
        evutil_gettimeofday(&newtime, NULL);
        evutil_timersub(&newtime, &g_last_time, &difference);
        elapsed = difference.tv_sec + (difference.tv_usec / 1.0e6);
        //流控过大取消发送事件
        if((double)(g_new_flow - g_last_flow) / elapsed > g_limit_flow)
        {
            event_del(nlc->get_ev_write());
            g_send_conn_deque.push_back(nlc->get_socket());
        }
    }

    char *tmp_send_buf = g_send_buf;

    int len = 0;
    //要发送的字节数
    int send_len = nlc->get_remain_data_len();
    if (nlc->get_remain_data_len() > (unsigned int)g_max_send_len)
    {
        send_len = g_max_send_len;
    }

	int random_type = g_random;
    //随机模式
    if (random_type == R_RANDOM)
    {
        gen_random_buf(g_send_buf, send_len);
        len = send(fd, g_send_buf, send_len, 0);
    }
    else if (random_type == R_ZERO)
    {
        len = send(fd, g_send_buf, send_len, 0);
    }
    else if (random_type == R_FILE)
    {
        //接着发送剩下的
        int off_base_len = g_send_buf_len - nlc->get_remain_data_len();
        char *tmp_send_buf = g_send_buf + off_base_len;
        len = send(fd, tmp_send_buf, send_len, 0);
    }
    else
    {
        //char send_buf[g_max_send_len + sizeof(unsigned int)];
        int bufsize = g_max_send_len + sizeof(unsigned int);
        send_buf = new char[bufsize];
        memset(send_buf,0,bufsize);
        unsigned int mask = nlc->get_mask();
        //接着发送剩下的
		int off_base_len = g_send_buf_len - nlc->get_remain_data_len();
        int i = 0;
        //冗余模式
		if (random_type == R_REDUNDANCY ||random_type == R_REDUNDANCY_NO_XOR)
		{
			for (i = 0; i < send_len; i++)
			{
				int mask_off = off_base_len + i;
                char cmask = ((char *)&mask)[mask_off % sizeof(unsigned int)];
                if (random_type == R_REDUNDANCY_NO_XOR) //与R_FILE效果一样，暂时留着占坑吧
                {
                    send_buf[i] = *(g_send_buf + mask_off);  
                }
                else
                {                    
                    send_buf[i] = *(g_send_buf + mask_off) ^ cmask;   
                }				             
                if (g_verbose)
                {
                    printf("mask_off %d = g_send_buf offset %d   cmask %d %c send_buf %c\n",
                        mask_off,mask_off,mask_off % sizeof(unsigned int),cmask,send_buf[i]);
                }
			}
		}
        //冗余混乱模式
		else if(random_type == R_REDUNDANCY_CHAOS ||random_type == R_REDUNDANCY_CHAOS_NO_XOR)
		{
			for (i = 0; i < send_len; i++)
			{
				int mask_off = off_base_len + i;
                int map_off = nlc->get_off_map(mask_off);
                char cmask = ((char *)&mask)[mask_off % sizeof(unsigned int)];
                if (random_type == R_REDUNDANCY_CHAOS_NO_XOR)
                {
                    send_buf[i] = *(g_send_buf + map_off);  
                }
                else
                {                    
                    send_buf[i] = *(g_send_buf + map_off) ^ cmask;  
                }				
                if (g_verbose)
                {
                    printf("mask_off %d = g_send_buf offset %d  cmask = %d 0x%x  send_buf = %c\n",
                        mask_off,map_off,mask_off % sizeof(unsigned int),cmask,send_buf[i]);
                }                
			}
		}

        len = send(fd, send_buf, send_len, 0);

        tmp_send_buf = send_buf;
    }

	if (len == 0)
    {
		close_client(fd);
		//return;
	}
	else if (len < 0 && (!is_try_again()))
    {
        fprintf(stderr, "send(%d) failed. len:%d, errno:%d, info:%s\n", 
            fd, len, EVUTIL_SOCKET_ERROR(), get_error_string(EVUTIL_SOCKET_ERROR()));
		close_client(fd);
		//return;
	}

    if(len > 0)
    {
        g_new_flow += len;
        int ret = nlc->on_send_data(tmp_send_buf, len);
        if (ret <= 0)
        {
            //return;
        }
    }
    if (send_buf != NULL)
    {
        delete[] send_buf;
        send_buf = NULL;
    }
/*
    if(event_add(nlc->get_ev_write(), NULL) != 0)
    {
        nlc->set_error_no(NL_CONN_ERROR_EV_WRITE);
        close_client(fd);
    }
    */
}

/**
 * This function will be called by libevent when there is a connection
 * ready to be accepted.
 */
static void on_accept(evutil_socket_t fd, short ev, void *arg)
{
	int client_fd;
	struct sockaddr_in client_addr;
	socklen_t client_len = (socklen_t)sizeof(client_addr);
	static int maxfd = 80000;
	
	client_fd = accept(fd, (struct sockaddr *)&client_addr, &client_len);
	if (client_fd == -1)
    {
        fprintf(stderr, "accept failed. errno:%d, info:%s\n", 
            EVUTIL_SOCKET_ERROR(), get_error_string(EVUTIL_SOCKET_ERROR()));
		return;
	}

	if(client_fd > maxfd + 1000)
    {
		maxfd = client_fd;
		printf("maxfd %d\n", maxfd );
	}

    if (g_tcp_send_buf_len >= 0)
    {
        setsockopt(client_fd, SOL_SOCKET, SO_SNDBUF, (const char*)&g_tcp_send_buf_len, sizeof(int));
    }
	
	if (g_no_delay)
	{
		int flag;
		setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag));
	}
	
//	setsockopt(client_fd, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&fd, sizeof(fd));
	
	/* Set the client socket to non-blocking mode. */
	if (evutil_make_socket_nonblocking(client_fd) < 0)
    {
		fprintf(stderr, "failed to set client socket non-blocking.\n");
    }

    server_conn *nlc = new server_conn(client_fd);
   	event_set(nlc->get_ev_read(), client_fd, EV_READ, on_read, nlc);
  	event_set(nlc->get_ev_write(), client_fd, EV_WRITE | EV_PERSIST, on_write, nlc);
    nlc->set_max_send_len(g_send_buf_len);
    if (!g_same)
    {
        nlc->set_mask((unsigned int)genrand64_int64());
    }
    nlc->set_block(g_block);
    nlc->set_check(g_check);
	nlc->set_alter(g_alter);
    nlc->set_debug_level(g_verbose);

 	printf("accepted connection(%d) from %s:%d.\n", client_fd, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    g_conns.insert(pair<int, server_conn *>(client_fd, nlc));
    printf("current connected sockets number:%u\n", (unsigned int)g_conns.size());

    if(event_add(nlc->get_ev_read(), NULL) != 0)
    {
        nlc->set_error_no(NL_CONN_ERROR_EV_READ);
        close_client(client_fd);
        fprintf(stderr, "event_add failed(%d) from %s:%d.\n", client_fd, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
 	}
}

void print_usage(bool detail = false)
{
    fprintf(stderr, "usage: conn_test_server -[hvpjgdmkfrblsecaqtznyVH] [options]\n");
    fprintf(stderr, "\t-h --help\n");
    fprintf(stderr, "\t-H --detailhelp      详细帮助\n");
    fprintf(stderr, "\t-v --version         版本\n");
    fprintf(stderr, "\t-p --port            指定使用的端口\n");
	fprintf(stderr, "\t-j --bind            指定使用的IP\n");
    fprintf(stderr, "\t-g --granularity     粒度\n");
    fprintf(stderr, "\t-d --duplicate       冗余填充模式\n");
    fprintf(stderr, "\t-m --same            所有连接相同模式\n");
    fprintf(stderr, "\t-k --block           数据粒度分块大小\n");
    fprintf(stderr, "\t-f --file            指定文件\n");
    fprintf(stderr, "\t-r --random          指定模式:0冗余 1随机 2全零 3冗余混乱 4冗余不加密 5冗余混乱不加密 6文件模式\n");
    fprintf(stderr, "\t-b --buffer          tcp接收和发送缓冲区大小(KB)，默认系统默认值\n");
	fprintf(stderr, "\t-l --length          默认一次发送最大数据长度，默认为4096\n");
    fprintf(stderr, "\t-s --seed            随机数随机化种子，默认按照当前时间随机\n");
	fprintf(stderr, "\t-e --scope           随机数生成模式，如果为32表示32位随机，其他表示64位随机，默认为64位随机\n");
    fprintf(stderr, "\t-c --check           校验数据\n");
	fprintf(stderr, "\t-a --alternative     交互模式\n");
	fprintf(stderr, "\t-q --nodelay         所有连接禁用Nagle算法，默认启用Nagle算法\n");
    fprintf(stderr, "\t-t --limit           流控限速，该功能精度较低，尤其在流控1MBps以下，不宜用在精度要求较高的场合\n");
    fprintf(stderr, "\t-z --multi-process   多进程模式，可以同时启用多个进程监听一个端口，仅在linux下有效且进程数必须小于64\n");
    fprintf(stderr, "\t-n --silent          后台运行模式\n");
	fprintf(stderr, "\t-y --http            监听HTTP端口号，显示连接数、流量和速度，默认不监听，多进程模式无法使用\n");
    fprintf(stderr, "\t-V --verbose         调试输出等级\n");

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
        {"port",    1, NULL, 'p'},
        {"bind",    1, NULL, 'j'},
        {"granularity",      1, NULL, 'g'},
        {"duplicate",        1, NULL, 'd'},
        {"same",    0, NULL, 'm'},
        {"block",   1, NULL, 'k'},
        {"file",    1, NULL, 'f'},
        {"random",  1, NULL, 'r'},
        {"buffer",  1, NULL, 'b'},
        {"length",  1, NULL, 'l'},
        {"seed",    1, NULL, 's'},
        {"scope",   1, NULL, 'e'},
        {"check",   0, NULL, 'c'},
        {"alternative",      0, NULL, 'a'},
        {"nodelay", 0, NULL, 'q'},
        {"limit",   1, NULL, 't'},
        {"multi-process",   1, NULL, 'z'},
        {"silent",  0, NULL, 'n'},
		{"http",    1, NULL, 'y'},
        {"verbose", 1, NULL, 'V'},
        {"detailhelp",    0, NULL, 'H'},
        {NULL,      0, NULL,   0}
    };

    const char* const short_options = "hvp:j:g:d:mk:f:r:b:l:s:e:caqt:z:ny:V:H";

    int ch = 0, tmp = 0;

    while ((ch = getopt_long(argc, argv, short_options, long_options, NULL)) != -1)
    {
        switch (ch)
        {
        case 'h':
            print_usage();
            return 0;
            break;
        case 'v':
            printf("conn_test_server 8.0 [%s] by yinwei\n", __DATE__);
            return 0;
            break;
        case 'p':
            g_port = atoi(optarg);
            if (g_port == 0)
            {
                fprintf(stderr, "port error.\n");
                return -1;
            }
            break;
        case 'j':
            strncpy(g_bind_ip_str, optarg, MAX_NAME_LEN);
            break;
        case 'g':
            g_send_buf_len = atobyte(optarg);
            if (g_send_buf_len <= 0)
            {
                fprintf(stderr, "granularity error.\n");
                return -1;
            }
            break;
        case 'd':
            g_duplicate_len = atobyte(optarg);
            if (g_duplicate_len <= 0)
            {
                fprintf(stderr, "duplicate error.\n");
                return -1;
            }
            break;
        case 'm':
            g_same = true;
            break;
        case 'e':
            tmp = atoi(optarg);
            if (tmp == 32)
            {
                g_scope = RANDOM_32;
            }
            else
            {
                g_scope = RANDOM_64;
            }
            break;
        case 'k':
            g_block = atobyte(optarg);
            if (g_block <= 1)
            {
                fprintf(stderr, "block error.\n");
                return -1;
            }
            break;
        case 'f':
            strncpy(g_in_file_name, optarg, TMP_READ_BUF - 1);
            break;
        case 'r':
            g_random = atoi(optarg);
            break;
        case 'b':
            g_tcp_send_buf_len = atoi(optarg);
            if (g_tcp_send_buf_len < 0)
            {
                fprintf(stderr, "buffer error.\n");
                return -1;
            }
            g_tcp_send_buf_len *= 1024;
            break;
        case 'l':
            g_max_send_len = atoi(optarg);
            if (g_max_send_len <= 0 || g_max_send_len > 1024 * 1024)
            {
                fprintf(stderr, "max send length error.\n");
                return -1;
            }
            break;          
        case 's':
            g_seed = atoi(optarg);
            if (g_seed <= 0)
            {
                fprintf(stderr, "seed error.\n");
                return -1;
            }
            break;
        case 'c':
            g_check = true;
            break;
        case 'a':
            g_alter = true;
            break;
        case 'q':
            g_no_delay = true;
            break;
        case 't':
            g_limit_flow = atobyte(optarg) * 1.1;
            if (g_limit_flow <= 0)
            {
                fprintf(stderr, "limit error.\n");
                return -1;
            }
            break;
        case 'z':
#ifdef WIN32
            fprintf(stderr, "multi-process is not support in the Windows!\n");
            break;
#endif
            g_process_number = atoi(optarg);
            if (g_process_number < 0 || g_process_number > 64)
            {
                fprintf(stderr, "process number error.\n");
                return -1;
            }
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
    return 1;
}

int init_listen_socket(evutil_socket_t &listen_fd)
{
    struct sockaddr_in listen_addr;

    /* Create our listening socket. This is largely boiler plate
     * code that I’ll abstract away in the future. */
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0)
    {
        fprintf(stderr, "create socket failed. errno:%d, info:%s\n", EVUTIL_SOCKET_ERROR(), get_error_string(EVUTIL_SOCKET_ERROR()));
        return -1;
    }

    int reuseaddr_on = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&reuseaddr_on,
        sizeof(reuseaddr_on)) == -1)
    {
        fprintf(stderr, "setsockopt failed. errno:%d, info:%s\n", EVUTIL_SOCKET_ERROR(), get_error_string(EVUTIL_SOCKET_ERROR()));
    }

    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;;
    listen_addr.sin_port = htons(g_port);
    
    if (strlen(g_bind_ip_str) > 0)
    {
        listen_addr.sin_addr.s_addr = inet_addr(g_bind_ip_str);
    }
    else
    {
        listen_addr.sin_addr.s_addr = INADDR_ANY;
    }

    if (bind(listen_fd, (struct sockaddr *)&listen_addr,
        sizeof(listen_addr)) < 0)
    {
        fprintf(stderr, "bind failed. errno:%d, info:%s\n", EVUTIL_SOCKET_ERROR(), get_error_string(EVUTIL_SOCKET_ERROR()));
        EVUTIL_CLOSESOCKET(listen_fd);
        return -1;
    }

    if (listen(listen_fd, 1024) < 0)
    {
        fprintf(stderr, "listen failed. errno:%d, info:%s\n", EVUTIL_SOCKET_ERROR(), get_error_string(EVUTIL_SOCKET_ERROR()));
        EVUTIL_CLOSESOCKET(listen_fd);
        return -1;
    }

    /* Set the socket to non-blocking, this is essential in event
     * based programming with libevent. */
    if (evutil_make_socket_nonblocking(listen_fd) < 0)
    {
        fprintf(stderr, "failed to set server socket to non-blocking.\n");
    }

    return 0;
}

// 填充发送缓冲区
int fill_send_buffer()
{
    if (g_duplicate_len > 0)
    {
        if (g_duplicate_len > g_send_buf_len)
        {
            fprintf(stderr, "the duplicate must be less than the granularity.\n");
            return -1;
        }

        if (g_send_buf_len % g_duplicate_len != 0)
        {
            fprintf(stderr, "granularity %% duplicate must be 0.\n");
            return -1;
        }
    }

    if (g_block > 0 && g_random != R_REDUNDANCY_CHAOS)
    {
        fprintf(stderr, "the block is valid only in redundancy chaos mode.\n");
    }
    else
    {
        if (g_block > g_send_buf_len)
        {
            fprintf(stderr, "the block must be less than the granularity.\n");
            return -1;
        }
    }

    if (g_random == R_REDUNDANCY_CHAOS)
    {
        if (g_block <= 0)
        {
            fprintf(stderr, "the block must be more than the zero.\n");
            return -1;
        }

        if (g_send_buf_len % g_block != 0)
        {
            fprintf(stderr, "granularity %% block must be 0.\n");
            return -1;
        }
    }

    if (strlen(g_in_file_name) > 0 && g_random != R_REDUNDANCY && g_random != R_REDUNDANCY_CHAOS 
        && g_random != R_FILE && g_random != R_REDUNDANCY_NO_XOR && g_random != R_REDUNDANCY_CHAOS_NO_XOR)
    {
        fprintf(stderr, "the file is valid only in redundancy or redundancy chaos mode.\n");
    }

    if (g_same && g_random != R_REDUNDANCY && g_random != R_REDUNDANCY_CHAOS)
    {
        fprintf(stderr, "the same mode is valid only in redundancy or redundancy chaos mode.\n");
    }
    
    if (g_check && !g_alter)
    {
        fprintf(stderr, "the check option and the alternative option conflict!\n");
        return -1;
    }

#ifdef WIN32
    srand(g_port);
#else
    srand(g_port + getpid());
#endif
    
    if (g_seed >= 0)
    {
        if (g_scope == RANDOM_64)
        {
            init_genrand64((unsigned long)g_seed + rand());
        }
        else
        {
            init_genrand((unsigned long)g_seed + rand());
        }
    }
    else
    {
        if (g_scope == RANDOM_64)
        {
            init_genrand64(time(NULL) + rand());
        }
        else
        {
            init_genrand(time(NULL) + rand());
        }
    }
/*    if (g_random == R_FILE)
    {
        unsigned long filesize = -1;      
        struct stat statbuff;  
        if(stat(g_in_file_name, &statbuff) < 0)
        {  
            fprintf(stderr, "can't get the file stat.\n");
            return -1;
        }else{  
            filesize = statbuff.st_size; 
            g_send_buf_len = filesize;
        }  
        g_send_buf = new char[g_send_buf_len];
    }    
    else */if (g_random == R_ZERO)
    {
        g_send_buf = new char[g_send_buf_len];
        memset(g_send_buf, 0, g_send_buf_len);
    }     
    else
    {
        g_send_buf = new char[g_send_buf_len];
        if (strlen(g_in_file_name) > 0)
        {
            FILE *in_fp = fopen(g_in_file_name, "r+b");
            if (in_fp == NULL)
            {
                fprintf(stderr, "open file %s failed.\n", g_in_file_name);
                delete []g_send_buf;
                return -1;
            }
            int read_len = 16 * 1024;
            int total_read_len = 0;
            int i = 0;
            //读取g参数设置的大小数
            for (i = 0; i < g_send_buf_len / read_len; i++)
            {
                int ret = fread(g_send_buf + i * read_len, 1, read_len, in_fp);
                if (ret < 0)
                {
                    break;
                }
                total_read_len += ret;
                if (ret < read_len)
                {
                    break;
                }
            }
            //读取剩余的
            if (i == g_send_buf_len / read_len)
            {
                int ret = fread(g_send_buf + i * read_len, 1, g_send_buf_len % read_len, in_fp);
                if (ret > 0)
                {
                    total_read_len += ret;
                }
            }

            if (total_read_len == 0)
            {
                fprintf(stderr, "empty file %s!\n", g_in_file_name);
                delete []g_send_buf;
                fclose(in_fp);
                return -1;
            }
            fclose(in_fp);
            //文件大小有可能比要发送的大小小，使用文件内容循环填充缓冲区
            for (i = 1; i < g_send_buf_len / total_read_len; i++)
            {
                memcpy(g_send_buf + i * total_read_len, g_send_buf, total_read_len);
            }
            
            if (g_send_buf_len % total_read_len != 0)
            {
                memcpy(g_send_buf + i * total_read_len, g_send_buf, g_send_buf_len % total_read_len);
            }
        }
        //没有指定文件
        else
        {
            if (g_duplicate_len > 0)
            {
                gen_random_buf(g_send_buf, g_duplicate_len);
                // 复制多份
                for (int i = 1; i < g_send_buf_len / g_duplicate_len; i++)
                {
                    memcpy(g_send_buf + i * g_duplicate_len, g_send_buf, g_duplicate_len);
                }
            }
            else
            {
                gen_random_buf(g_send_buf, g_send_buf_len);
            }
        }
    }

    return 0;
}

void generic_request_handler(struct evhttp_request *req, void *arg)
{
    struct evbuffer *returnbuffer = evbuffer_new();
	evhttp_add_header(req->output_headers, "Content-Type", "text/html; charset=UTF-8");
    evhttp_add_header(req->output_headers, "Server", "conn_test_server");
    evhttp_add_header(req->output_headers, "Connection", "close");
	
	evbuffer_add_printf(returnbuffer, "<html><head><title>conn_test_server</title>");

	evbuffer_add_printf(returnbuffer, "<meta http-equiv=\"refresh\" content=\"%d\"/>", 1);

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

    evutil_socket_t listen_fd;

    if (init_listen_socket(listen_fd) < 0)
    {
#ifdef WIN32
        WSACleanup();
#endif
        return -1;
    }

    printf("listening on port %d.\n", g_port);

#ifndef WIN32
    int i = 0; 
    for(i = 0; i < g_process_number; i++) 
    {    
         pid_t pid = fork();
         if (pid == 0)
         {
             break;
         }
         else if (pid < 0)
         {
             fprintf(stderr, "fork failed!, errno:%d, info:%s\n", errno, get_error_string(errno));
         }
         else 
         {
             g_child_pid[i] = pid;    
             printf("fork child process. pid:%u\n", pid);
         }    
    }    

    if (g_process_number != 0 && i == g_process_number)
    {    
        for(int i = 0; i < g_process_number; i++)
        {    
            if (g_child_pid[i] != 0)
            {
                waitpid(g_child_pid[i], NULL, 0);
            }
        }

        EVUTIL_CLOSESOCKET(listen_fd);
        return 0; 
    }
#endif

    if (fill_send_buffer() < 0)
    {
        EVUTIL_CLOSESOCKET(listen_fd);
#ifdef WIN32
        WSACleanup();
#endif
        return -1;
    }

    /* Initialize libevent. */
    g_evbase = event_init();
	printf("event method:%s.\n", event_base_get_method(g_evbase));

    struct event *ev_accept = new event;

	/* We now have a listening socket, we create a read event to
	 * be notified when a client connects. */
	event_set(ev_accept, listen_fd, EV_READ | EV_PERSIST, on_accept, NULL);
	event_add(ev_accept, NULL);

    if (g_limit_flow > 0.0)
    {
        struct event timeout;
        struct timeval tv;
        int flags = 0;

        /* Initalize one event */
        event_assign(&timeout, g_evbase, -1, flags, timeout_cb, (void*) &timeout);
        //evtimer_set(&timeout, timeout_cb, &timeout);

        evutil_timerclear(&tv);
        tv.tv_sec = 0;
        tv.tv_usec = 10000;
        event_add(&timeout, &tv);
        
        evutil_gettimeofday(&g_last_time, NULL);
    }

	if (g_http_port > 0 && g_process_number == 0)
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

        struct event timeout;
        struct timeval tv;
        int flags = 0;

        /* Initalize one event */
        event_assign(&timeout, g_evbase, -1, flags, timeout_show_cb, (void*) &timeout);
        //evtimer_set(&timeout, timeout_cb, &timeout);

        evutil_timerclear(&tv);
        tv.tv_sec = 1;
        event_add(&timeout, &tv);
        
        evutil_gettimeofday(&g_last_show_time, NULL);
    }
	
    /* Start the libevent event loop. */
    event_dispatch();

    delete []g_send_buf;

    while (!g_conns.empty())
    {
        map <int, server_conn *>::iterator it = g_conns.begin();
        it->second->set_error_no(NL_CONN_ERROR_SEVER_STOP);
        close_client(it->first);
    }

    EVUTIL_CLOSESOCKET(listen_fd);

#ifdef WIN32
	WSACleanup();
#endif

	return 0;
}
