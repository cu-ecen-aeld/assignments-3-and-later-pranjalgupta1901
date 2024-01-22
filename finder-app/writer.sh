#!/bin/bash

if [ "$#" -ne 2 ]; then
	echo "Either Directory or String is not specified"
	exit 1
fi

if [ ! -n "$2" ]; then 
	echo "Second Argument $2 is empty string"
	exit 1
fi

mkdir -p "$(dirname "$1")"

echo "$2" > "$1"

if [ ! -e "$1" ]; then
	echo "The file $1 could not be created"
	exit 1
fi

