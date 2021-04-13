#!/bin/bash

cd tests

for outfile in *.out
do


    file=${outfile%.out}
    #outfile=$(echo $file | sed 's/in/out/')

    echo "testing: $file"

    diff -w -B <(../trace ${file}) ${outfile}
    #diff -w -B ${outfile} <(./run.sh ${file})

done
