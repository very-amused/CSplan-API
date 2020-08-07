#! /bin/bash

# This script will look for queries in the routes folder that were not closed,
# and report the relevant line number so that the problem may be fixed.
# Running this script precommit is helpful to prevent connection leaks.

exit=0
for file in routes/*.go; do
	i=0
	while read line; do
		i=$((i+1)) # Keep track of line number
		if [[ $line =~ DB\.Query ]]; then
			open=true
			open_line=$i
		elif [[ $line =~ '.Close()' ]]; then
			open=false
		elif [[ $line == '}' && $open == 'true' ]]; then
			exit=1
			echo "Query not closed in $file, line $open_line."
			open=false
		fi
	done < $file
done

exit $exit
