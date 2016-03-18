sort.exe -n out1.txt > tmp.txt
conn_test_stat tmp.txt 100 > out1_a.txt
sort.exe -n out1r.txt > tmp.txt
conn_test_stat tmp.txt 100 > out1r_a.txt

sort.exe -n out2.txt > tmp.txt
conn_test_stat tmp.txt 17 > out2_a.txt
sort.exe -n out2r.txt > tmp.txt
conn_test_stat tmp.txt 17 > out2r_a.txt

sort.exe -n out3.txt > tmp.txt
conn_test_stat tmp.txt 4 > out3_a.txt
sort.exe -n out3r.txt > tmp.txt
conn_test_stat tmp.txt 4 > out3r_a.txt

sort.exe -n out4.txt > tmp.txt
conn_test_stat tmp.txt 2 > out4_a.txt
sort.exe -n out4r.txt > tmp.txt
conn_test_stat tmp.txt 2 > out4r_a.txt