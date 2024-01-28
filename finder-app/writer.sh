#!/bin/bash

#checking the number of arguments which should be 2
if [ "$#" -ne 2 ]; then
	echo "Either Directory or String is not specified"
	exit 1
fi

#checking if the given string is non empty or empty
if [ ! -n "$2" ]; then 
	echo "Second Argument $2 is empty string"
	exit 1
fi


#making the directory by extracting the directory from the complete pathname which include the file name also
mkdir -p "$(dirname "$1")"

#writing the string into the desired file by creating first if it does not exist
echo "$2" > "$1"

#checking if the file was created or not
if [ ! -e "$1" ]; then
	echo "The file $1 could not be created"
	exit 1
fi

