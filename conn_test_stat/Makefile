# 修改生成可执行文件的名称
EXECUTABLE := conn_test_stat
# 修改LIBS，添加所需要链接的库，以空格分隔，例如 LIBS := pthread rt ssl
LIBS :=# Now alter any implicit rules’ variables if you like, e.g.:
#
# 修改CC，改变编译器
CC := g++
# 修改编译选项
CFLAGS := -O2 -Wall
CXXFLAGS := $(CFLAGS)
RM-F := rm -f
LDFLAGES := 

# You shouldn’t need to change anything below this point.
#
#匹配的文件，默认仅匹配当前目录，可做如下修改
#可添加所需要包含的目录，例如$(wildcard test/*.cpp)
#可添加所支持的后缀文件，例如$(wildcard *.cc)
SOURCE := $(wildcard *.c) $(wildcard *.cpp)
OBJS := $(patsubst %.c,%.o,$(patsubst %.cpp,%.o,$(SOURCE)))
DEPS := $(patsubst %.o,%.d,$(OBJS))
MISSING_DEPS := $(filter-out $(wildcard $(DEPS)),$(DEPS))
MISSING_DEPS_SOURCES := $(wildcard $(patsubst %.d,%.c,$(MISSING_DEPS)) \
$(patsubst %.d,%.cc,$(MISSING_DEPS)))
CPPFLAGS += -MD
 
.PHONY : all deps objs clean veryclean rebuild

all : $(EXECUTABLE)

deps : $(DEPS)

objs : $(OBJS)

clean :
	@$(RM-F) *.o
	@$(RM-F) *.d
	@$(RM-F) $(EXECUTABLE)

rebuild: clean all

ifneq ($(MISSING_DEPS),)
$(MISSING_DEPS) :
	$(RM-F) $(patsubst %.d,%.o,$@)
endif

$(EXECUTABLE) : $(OBJS)
	$(CC) -o $(EXECUTABLE) $(LDFLAGES) $(OBJS) $(addprefix -l,$(LIBS))
