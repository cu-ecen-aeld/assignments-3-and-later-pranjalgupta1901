#!/bin/bash

if [ "$#" -ne 2 ]; then
	echo "Either Directory or String is not specified"
	exit 1
fi

if [ ! -d "$1" ]; then
	echo "First argument is not a directory"
	exit 1
fi

if [ ! -n "$2" ]; then 
	echo "Second Argument is empty string"
	exit 1
fi


myvar_x=$( ls "$1" | wc -l )

myvar_y=$( grep -r "$2" "$1" | wc -l )

echo "The number of files are $myvar_x and the number of matching lines are $myvar_y"

