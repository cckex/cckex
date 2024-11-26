set datafile separator ','

#set term png size 700,700

#set term epslatex color
#set out "modified_data_percent.tex"

set term pdf color
set out "modified_data_percent.pdf"

set style fill solid 0.5 border -1
set style data boxplot
set boxwidth  0.5
set pointsize 0
set style boxplot nooutliers medianlinewidth 2.5

unset key
set xtics ("TCP Urgent \n Pointer CC" 1, "Envelope \n Injection CC" 2, "Message ProtoBuf \n Injection CC" 3) scale 0.0 font ", 12"
set xtics nomirror
set ytics nomirror
set yrange [*:*]

set bmargin 3

set ylabel "Relative modified data per package"

plot "all_stats_dump.csv" using (1):($6/$5) title "Payload in Urgent Pointer CC" lc "grey60", \
					   "" using (2):($3 == 0 ? 1/0 : ($6 + $3) / $5) title "Payload in Envelope Injection CC" lc "grey60", \
					   "" using (3):($3 == 0 || $4 == 0 ? 1/0 : ($6 + $3 + $4) / $5) title "Payload in Message Padding Injection CC" lc "grey60"
