#!/bin/bash

clean_input_file()
{
    if [ -f sig_results.txt ]
    then
        rm sig_results.txt 
    fi
}

echo "TESTING BEGIN..."

for directory in $(ls pcap)
do
    procent_sum=0
    num_files=0
    path="pcap/"$directory"/"
    correct_solution=$(echo ${path:5} | tr -d "/" )

    for file in $(ls pcap/$directory/[1-9]_*.pcap)
    do
	    matches_num=0
	    let num_files=$num_files+1;
        file=${file#*/*/} # формируем имя файла 
	    session_num=${file:0:1} # узнаем сколько сессий содержится в pcap файле

	    ./main -m offline -d $path$file -s debug # формируется файл с результатом

        while read solution # читаем файл с решениями программы
        do
            if [[ "$solution" == "$correct_solution" ]]
	        then
		        let matches_num=$matches_num+1 # инкрементируем количество совпадений
	        fi
	    done < sig_results.txt

	    if [[ "$matches_num" -gt "$session_num" ]] # высчитываем процент совпадений
	    then
            procent_sum=$(echo "scale=3; $procent_sum+1" | bc) 
	    else
	        procent=$(echo "scale=3; $matches_num/$session_num" | bc) 
            procent_sum=$(echo "scale=3; $procent_sum+$procent" | bc)
	    fi
            
        echo "Traffic type: "$correct_solution"     File: "$file"  ->  "$matches_num"  match in  "$session_num"  sessions"        
	    clean_input_file
    done
    final_proc=$(echo "scale=3; $procent_sum*100/$num_files" | bc);
    echo $correct_solution " matches  "$final_proc
done
