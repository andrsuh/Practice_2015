#!/bin/bash
rm build/expected_results.txt build/results.txt build/tmp.txt
for DIR in $(ls pcap/test)
do
    t=0
    pred=0
    for FILE in $(ls pcap/test/$DIR/*.pcap ) 
   do
       before=$(cat build/results.txt | wc -l)  
        ./main -a determine -m offline -d $FILE -s release
        after=$(cat build/results.txt | wc -l)
       i=0
       let LIMIT=$after-$before
       while [[ "$i" -lt "$LIMIT" ]]
       do
           echo $FILE $DIR>> build/expected_results.txt
           let i=$i+1   # допускается var0=$(($var0+1))
        done
   done
done

exec < build/expected_results.txt
exec 7<&0
exec < build/results.txt
exec 6<&0

vv=0
vb=0
bv=0
vd=0
dv=0
dnd=0
db=0
bd=0
bb=0
all=0
while read line2
do
	let all=$all+1
	exec 0<&7 
	read line1
	exec 0<&6 
	echo $line1 $line2 
	let vv=$vv+$(echo $line1 $line2 |  grep -E ' video.* video' | wc -l)
	let vb=$vb+$(echo $line1 $line2 |  grep -E ' video.* brows' | wc -l)
	let bv=$bv+$(echo $line1 $line2 |  grep -E ' brows.* video' | wc -l)
	let vd=$vd+$(echo $line1 $line2 | grep -E ' video.* down'  | wc -l)
	let dv=$dv+$(echo $line1 $line2 | grep -E ' down.* video' | wc -l)
	let dnd=$dnd+$(echo $line1 $line2 |  grep -E ' down.* down' | wc -l)
	let db=$db+$(echo $line1 $line2 | grep -E ' down.* brows'  | wc -l)
	echo $line1 $line2 | grep -E ' down.* brows' 
	let bd=$bd+$(echo $line1 $line2 |  grep -E ' brows.* down' | wc -l)
	let bb=$bb+$(echo $line1 $line2 |grep -E ' brows.* brows'  | wc -l)
	echo $vv $vb $vd $bb $bd $bv $dnd $dv $db $all
done
exec 7<&-
exec 6<&-
echo $(echo "scale=3; 0*100/($vv+$vd+$vb)" | bc)
echo $vv $vb $vd $bb $bd $bv $dnd $dv $db $all

#первый столбец это то, что должно вывести!!
mvb=$(echo "scale=3; $vb*100/($vv+$vd+$vb)" | bc) 
echo "путаем video с browsing" $mvb "%"
mvb=$(echo "scale=3; $vd*100/($vv+$vd+$vb)" | bc) 
echo "путаем video с download" $mvb "%"
mvb=$(echo "scale=3; $vv*100/($vv+$vd+$vb)" | bc) 
echo "определили правильно video" $mvb "%"

mvb=$(echo "scale=3; $bv*100/($bv+$bd+$bb)" | bc) 
echo "путаем browsing с video" $mvb "%"
mvb=$(echo "scale=3; $bd*100/($bv+$bd+$bb)" | bc) 
echo "путаем browsing с download" $mvb "%"
mvb=$(echo "scale=3; $bb*100/($bv+$bd+$bb)" | bc) 
echo "правильно определяем browsing" $mvb "%"

mvb=$(echo "scale=3; $db*100/($db+$dnd+$dv)" | bc) 
echo "путаем download с browsing" $mvb "%"
mvb=$(echo "scale=3; $dv*100/($db+$dnd+$dv)" | bc) 
echo "путаем download с video" $mvb "%"
mvb=$(echo "scale=3; $dnd*100/($db+$dnd+$dv)" | bc) 
echo "правильно определяем download" $mvb "%"

mvb=$(echo "scale=3; ($vv+$dnd+$bb)*100/$all" | bc) 
echo "Общая эффективность" $mvb

#diff expected_results.txt results.txt --side-by-side
#t=$(cat results.txt | wc -l)
#q=$(cat expected_results.txt | wc -l)
#let r=t-$(diff expected_results.txt results.txt --side-by-side --suppress-common-lines | wc -l )
#result=$(echo "scale=3; $r*100/$t" | bc) 
#echo $r $t $q $result


