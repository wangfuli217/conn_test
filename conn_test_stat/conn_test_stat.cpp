#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PATH_LEN 266

int main(int argc, char *argv[])
{
    int repeat = 10;
    char path_out[MAX_PATH_LEN];
    if (argc <= 1)
    {
        printf("please input data filename.\n");
        return 0;
    }

    strncpy(path_out, argv[1], MAX_PATH_LEN);

    if (argc > 2)
    {
        int tmp = atoi(argv[2]);
        if (tmp > 0)
        {
            repeat = tmp;
        }
    }

    FILE *fp = fopen(path_out, "r");
    if (fp == NULL)
    {
        printf("open %s failed.\n", path_out);
        return 0;
    }

    double *spend_data = new double[repeat];
    double tav_data = 0.0;

    int count = 0;
    while(!feof(fp))
    {
        int id;
        int seq;
        double spend;
        int ret = fscanf(fp, "%d\t%d\t%lf\n", &id, &seq, &spend);
        if (ret != 3)
        {
            break;
        }
        spend_data[count % repeat] = spend;
        if (count % repeat == repeat - 1)
        {
            double av_data = 0.0;
            int i = 0;
            for (i = 0; i < repeat; i++)
            {
                av_data += spend_data[i];
            }
            av_data /= repeat;

            double va_data = 0.0;
            for (i = 0; i < repeat; i++)
            {
                va_data += (spend_data[i] - av_data) * (spend_data[i] - av_data);
            }
            va_data = sqrt(va_data);
            printf("%d\t%f\t%f\n", id, av_data, va_data);
        }

        tav_data += spend;
        count++;
    }

    if (count > 0)
    {
        printf("total average:%f\n", tav_data / count);
    }

    delete []spend_data;

    fclose(fp);
    
    return 0;
}
