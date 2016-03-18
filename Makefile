all : client server stat

client:
	make -C ./conn_test_client

server:
	make -C ./conn_test_server

stat:
	make -C ./conn_test_stat

clean :
	make clean -C ./conn_test_client
	make clean -C ./conn_test_server
	make clean -C ./conn_test_stat

rebuild: clean all
