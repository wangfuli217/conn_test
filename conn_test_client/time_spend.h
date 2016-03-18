#ifndef _TIME_SPEND_H_
#define _TIME_SPEND_H_

#ifdef WIN32
#include <windows.h>

class time_spend
{
public:
	time_spend() : m_last(current()), m_freq(get_freq())
    {}
    
    double spend() const{					//	���ش��ϴθ�λ��ʱ��������Ϊֹ��ʱ��������λΪms
        return (current()-m_last)*1000.0/m_freq;
    }
    double spend_reset(){					//	���ش��ϴθ�λ��ʱ��������Ϊֹ��ʱ��������λΪms������λ��ʱ��
        double t = m_last;
        m_last = current();
        return (m_last-t)*1000.0/m_freq;
    }
    void reset(){							//	��λ��ʱ��
        m_last = current();
    }	
    
    static double current(){				//	�߾��ȼ�ʱ����ǰ����ֵ
        LARGE_INTEGER cur;
        QueryPerformanceCounter(&cur);
        return (double)cur.QuadPart;
    }
    static double get_freq(){				//	�߾��ȼ�ʱ����Ƶ�ʣ�1����
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
    
    double spend() const{					//	���ش��ϴθ�λ��ʱ��������Ϊֹ��ʱ��������λΪms
        return current()-m_last;		
    }
    double spend_reset(){					//	���ش��ϴθ�λ��ʱ��������Ϊֹ��ʱ��������λΪms������λ��ʱ��
        double t = m_last;
        m_last = current();
        return m_last-t;
    }
    void reset(){							//	��λ��ʱ��
        m_last = current();
    }
    
    static double current(){				//	�߾��ȼ�ʱ����ǰ����ֵ
        timeval tv;
        gettimeofday(&tv, 0);
        return (double)tv.tv_sec*1000+(double)tv.tv_usec/1000;
    }
private:
    double m_last;
};
#endif

#endif // _TIME_SPEND_H_
