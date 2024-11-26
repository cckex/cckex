set datafile separator ','

set term png size 700,700

set style fill solid 0.5 border -1
set style boxplot outliers pointtype 7
set style data boxplot
set boxwidth  0.5
set pointsize 0.5

unset key
set border 2
set xtics ("Message Injection Payload Size" 1) scale 0.0
set xtics nomirror
set ytics nomirror
set yrange [0:180]

plot "all_stats_dump.csv" using (1):4 title "Possible Message Injection Payload Size"
