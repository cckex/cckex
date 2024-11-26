set datafile separator ','

#set term png size 1200,1000
#set out "payload_over_pkgs.png"

#set term epslatex color
#set out "payload_over_pkgs.tex"

set term pdf color
set out "payload_over_pkgs.pdf"

set style line 1 lc "black" pi 60 lw 1 ps 0.5
set style line 2 lc "gray40" pi 60 lw 1 ps 0.5
set style line 3 lc "red" pi 60 lw 1 ps 0.5
set style line 4 lc "blue" pi 60 lw 1 ps 0.5

set key invert top left Left reverse

set ylabel "Covertly Transmitted Bytes"
set xlabel "Package Number"

y1=0.
y2=0.
y3=0.
y4=0.
plot "stats_dump.csv" u 1:(y1=y1+$6) title "TCP Urgent Pointer CC" with lp ls 1, \
	 "stats_dump.csv" u 1:(y2=y2+$3) title "Envelope Injection CC" with lp ls 2, \
	 "stats_dump.csv" u 1:(y3=y3+$4) title "Random Message ProtoBuf Injection CC" with lp ls 3, \
	 "stats_dump.csv" u 1:(y4=y4+$7) title "Fixed Message ProtoBuf Injection CC" with lp ls 4
