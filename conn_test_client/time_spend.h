#ifndef _TIME_SPEND_H_
#define _TIME_SPEND_H_

#ifdef WIN32
#include <windows.h>

class time_spend
{
public:
	time_spend() : m_last(current()), m_freq(get_freq())
    {}
    
    double spend() const{					//	返回从上次复位计时器到现在为止的时间间隔，单位为ms
        return (current()-m_last)*1000.0/m_freq;
    }
    double spend_reset(){					//	返回从上次复位计时器到现在为止的时间间隔，单位为ms，并复位计时器
        double t = m_last;
        m_last = current();
        return (m_last-t)*1000.0/m_freq;
    }
    void reset(){							//	复位计时器
        m_last = current();
    }	
    
    static double current(){				//	高精度计时器当前的数值
        LARGE_INTEGER cur;
        QueryPerformanceCounter(&cur);
        return (double)cur.QuadPart;
    }
    static double get_freq(){				//	高精度计时器的频率，1秒钟
        LARGE_INTEGER freq;
        QueryPerformanceFrequency(&freq);
        return (double)freq.QuadPart;
    }
private:
    double m_last;
    double m_freq;
};
#else
#include <sys/time.h>
class time_spend
{
public:
    time_spend() : m_last(current())
    {}
    
    double spend() const{					//	返回从上次复位计时器到现在为止的时间间隔，单位为ms
        return current()-m_last;		
    }
    double spend_reset(){					//	返回从上次复位计时器到现在为止的时间间隔，单位为ms，并复位计时器
        double t = m_last;
        m_last = current();
        return m_last-t;
    }
    void reset(){							//	复位计时器
        m_last = current();
    }
    
    static double current(){				//	高精度计时器当前的数值
        timeval tv;
        gettimeofday(&tv, 0);
        return (double)tv.tv_sec*1000+(double)tv.tv_usec/1000;
    }
private:
    double m_last;
};
#endif

#endif // _TIME_SPEND_H_
