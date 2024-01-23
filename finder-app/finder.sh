#!/bin/bash

#checking if there are exact two arguments or not
if [ "$#" -ne 2 ]; then
	echo "Either Directory or String is not specified"
	exit 1
fi

#Checking if the first argument is directory of not
if [ ! -d "$1" ]; then
	echo "First argument is not a directory"
	exit 1
fi

#checking if the string is empty or non-empty
if [ ! -n "$2" ]; then 
	echo "Second Argument is empty string"
	exit 1
fi

#calculating the files inside the given the given directory
myvar_x=$( ls "$1" | wc -l )

#counting the lines in the given directory which includes the files with given string
myvar_y=$( grep -r "$2" "$1" | wc -l )

echo "The number of files are $myvar_x and the number of matching lines are $myvar_y"

