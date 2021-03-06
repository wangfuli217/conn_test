﻿const char *conn_help = \
"1.conn_test_server\n"
"(1)        -h --help\n"
"使用帮助。\n"
"(2)        -v --version\n"
"软件版本。\n"
"(3)        -p --port\n"
"监听端口号，默认5555。\n"
"(4)        -j --bind\n"
"绑定IP地址，默认绑定任意IP地址。\n"
"(5)        -g --granularity\n"
"服务端发送数据粒度大小，默认为1M。\n"
"说明：在交互模式下，也就是一个交互服务端发送数据的大小。\n"
"(6)        -d --duplicate\n"
"一个回复数据粒度数据重复量的大小，必须能被granularity整除，默认等于granularity。\n"
"(7)        -m --same\n"
"开启每条连接数据相同模式，只在粒度冗余模式和混乱模式下有效，默认不开启。\n"
"(8)        -r --random\n"
"表示数据随机性质，默认值为1。\n"
"0 数据按照设定粒度大小冗余，每一遍的数据是一样的\n"
"1 数据完全随机。\n"
"2 数据全0。\n"
"3 混乱模式，每一遍的数据都不一样。\n"
"4 冗余不加密模式，比冗余模式的数据要更加乱一些\n"
"5 混乱不加密模式，比3更乱，基本上是随机数据。\n"
"6 文件模式，用TCP协议发送指定的文件。\n"
"说明：混乱模式指在一个数据粒度内，按照block个块随机打乱顺序待发送数据。此种模式对流缓存效果和性能来说是个噩梦。\n"
"(9)        -k --block\n"
"混乱模式下数据粒度分块的大小，其他模式无效。分块大小必须能被数据粒度整除。\n"
"(10)       -b --buffer\n"
"tcp接收和发送缓冲区大小(KB)，默认系统默认值。\n"
"说明：在主机内存较小，而又需要跑很多连接的情况下，可把此值改小，甚至是0。如果需要跑很少的连接，并且又需要跑大吞吐，可以将此值设置尽量大一些，如1024。\n"
"(11)       -l --length\n"
"默认一次发送最大数据长度，默认为4096。\n"
"(12)       -s --seed\n"
"随机数随机化种子，默认按照当前时间随机。\n"
"说明：指定了随机化种子后，随机模式或其他随机情况的序列基本确定，对测试流缓存第二遍有用，但需要重启程序。\n"
"(13)       -f --file\n"
"数据文件路径，在粒度冗余模式和混乱模式下，数据可从文件导入。\n"
"说明：如果文件大小小于发送数据粒度，那么文件数据将缓存重复填满发送数据粒度缓冲区。\n"
"(14)       -e --scope\n"
"随机数生成模式，如果为32表示32位随机，其他表示64位随机，默认为64位随机。\n"
"(15)       -c --check\n"
"校验数据正确性，如果有错，程序退出，默认不校验。\n"
"(16)       -a --alternative\n"
"开启交互式发包，默认非交互。\n"
"说明：非交互模式下，不能和校验选项同时启用。\n"
"(17)       -q --nodelay\n"
"所有连接禁用Nagle算法，默认启用Nagle算法。\n"
"(18)       -t --limit\n"
"流控限速，该功能精度较低，尤其在流控1MBps以下，不宜用在精度要求较高的场合。\n"
"(19)       -z --multi-process\n"
"多进程模式，可以同时启用多个进程监听一个端口，仅在linux下有效且进程数必须小于64。\n"
"(20)       -n --silent\n"
"无声模式，即后台运行模式。\n"
"(21)       -y --http\n"
"监听HTTP端口号，显示连接数、流量和速度，默认不监听，多进程模式无法使用。\n"
"\n"
"2.conn_test_client\n"
"(1)        -h --help\n"
"使用帮助。\n"
"(2)        -v --version\n"
"软件版本。\n"
"(3)        -i --ip\n"
"连接IP地址，默认127.0.0.1。\n"
"(4)        -p --port\n"
"连接端口号，默认5555\n"
"(5)        -j --bind\n"
"绑定IP地址，默认系统选择。\n"
"(6)        -g --granularity\n"
"服务端发送数据粒度大小，默认为1M。\n"
"说明：在交互模式下，也就是一个交互服务端发送数据的大小，这个值必须跟服务端保持一致，否则程序退出。\n"
"(7)        -c --count\n"
"连接数数量，默认1个。\n"
"(8)        -r --repeat\n"
"请求的重复次数，默认为无限次，如果设置成0，则表示无限重复。\n"
"说明：如果需要长时间跑数据，这个值需要改大，但不能越过32位整形，如100000000。因此：一条连接传输的数据量=granularity*repeat。\n"
"(9)        -o --out\n"
"数据输出路径，默认当前路径out.txt文件，仅在交互模式下有效。\n"
"文件第一列表示连接序号，第二列表示第几次交互，第三列表示本次交互时间(ms)。\n"
"(10)       -d --delay\n"
"连接建立的延迟，默认0ms。\n"
"说明：服务端监听队列为1024，因此如果连接数大于1024，最好设置此值，如10，以免连接建立不成功。\n"
"(11)       -b --buffer\n"
"tcp接收和发送缓冲区大小，默认系统默认值。\n"
"说明：在主机内存较小，而又需要跑很多连接的情况下，可把此值改小，甚至是0(KB)。如果需要跑很少的连接，并且又需要跑大吞吐，可以将此值设置尽量大一些，如1024(KB)。\n"
"(12)       -l --relay\n"
"接力模式接力次数，默认不为接力模式。接力模式指前一个连接断开后才能开始后一个连接。\n"
"说明：持续跑短连接需要设置该选项的值\n"
"(13)       -t --time\n"
"显示传输速度的间隔时间，默认为1s，如果设置成0，则不显示。\n"
"(14)       -a --alternative\n"
"开启交互式发包，默认非交互。\n"
"说明：此值必须和服务端设置一致。\n"
"(15)       -q --nodelay\n"
"所有连接禁用Nagle算法，默认启用Nagle算法。\n"
"(16)       -n --silent\n"
"无声模式，即后台运行模式。\n"
"(17)       -y --http\n"
"监听HTTP端口号，显示连接数、流量和速度，默认不监听。\n"
"\n"
"3.sort\n"
"gnu的sort Windows实现，linux系统自带不需要。\n"
"对输出的数据进行排序，使用示例sort -n out.txt > out2.txt。\n"
"\n"
"4.conn_test_stat\n"
"参数只有一个，即请求重复次数，默认为10次。\n"
"对sort处理后的数据进行分析，包括每条连接的平均响应时间、方差以及总的响应时间。\n"
"\n"
"5.示例(服务端ip为1.1.1.1)\n"
"\n"
"(1)单条连接长时间跑大吞吐随机数据\n"
"服务端：conn_test_server -p 6000 -b 1024\n"
"客户端：conn_test_client -i 1.1.1.1 -p 6000 -b 1024\n"
"\n"
"(2)5000连接长时间跑大吞吐（按照每个连接200M数据重复）\n"
"服务端：conn_test_server -p 6000 -g 200M -r 0\n"
"客户端：conn_test_client -i 1.1.1.1 -p 6000 -g 200M -c 5000 -d 10\n"
"\n"
"(3)5000连接长时间跑大吞吐（按照每个连接1M数据重复），并且每隔2s显示一次速度\n"
"服务端：conn_test_server -p 6000 -d 1M -r 0\n"
"客户端：conn_test_client -i 1.1.1.1 -p 6000 -c 5000 -d 10 -t 2\n"
"\n"
"(4)1000并发短连接（每个连接发送1K随机数据，-a不是必须的，但加了可以使连接尽量正常关闭）\n"
"服务端：conn_test_server -p 6000 -g 1K -a\n"
"客户端：conn_test_client -i 1.1.1.1 -p 6000 -g 1K -c 1000 -r 1 -l 100000000 -a\n"
"\n"
"(5)1000并发连接跑1K随机交互数据\n"
"服务端：conn_test_server -p 6000 -g 1K -a\n"
"客户端：conn_test_client -i 1.1.1.1 -p 6000 -g 1K -c 1000 -a\n"
"\n"
"(6)10M文件a.dat按照4096字节一个块随机打乱并使用一个连接传输数据\n"
"服务端：conn_test_server -p 6000 -g 10M -r 3 -k 4096 -f a.dat\n"
"客户端：conn_test_client -i 1.1.1.1 -p 6000 -g 10M\n"
"\n"
"(7)常用功能速查\n"
"a.单连接第一遍\n"
"服务端：conn_test_server\n"
"客户端：conn_test_client -i 1.1.1.1\n"
"\n"
"b.单连接第二遍\n"
"服务端：conn_test_server -r 0\n"
"客户端：conn_test_client -i 1.1.1.1\n"
"\n"
"c.1000连接第一遍\n"
"服务端：conn_test_server\n"
"客户端：conn_test_client -i 1.1.1.1 -c 1000\n"
"\n"
"d.1000连接第二遍\n"
"服务端：conn_test_server -r 0\n"
"客户端：conn_test_client -i 1.1.1.1 -c 1000\n"
"\n"
"注意：linux系统开启大量连接跑数据前，需查看是否需要修改文件描述符限制（使用ulimit -n查看和修改）。\n"
;
