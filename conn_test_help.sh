#! /bin/sh
cp ʹ��˵��.txt man.txt
dos2unix man.txt
echo "const char *conn_help = \\" > conn_test_help.h
awk '{printf("\"%s\\n\"\n", $0)}' man.txt >> conn_test_help.h
echo ";" >> conn_test_help.h