#!/bin/bash
INPUT_DIR="../../../ACL_dataset"

outputfile="./out.stat"

>$outputfile


th_b=4
th_c=32


for i in acl1 acl2 acl3 acl4 acl5 fw1 fw2 fw3 fw4 fw5 ipc1 ipc2
do
    for j in 256k
    do
        filter="$i"_$j
        echo $filter
        rf="$INPUT_DIR"/"$filter".txt
        tf="$INPUT_DIR"/"$filter"_trace-1.txt
        echo $filter >> $outputfile
        taskset -c 3 ./main -r $rf -p $tf>>$outputfile
    done
done
