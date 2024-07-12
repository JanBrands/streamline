#!/bin/bash

DIR="$(dirname "$(readlink -f "$0")")"

if [[ -z "$1" ]]; then
    echo "[INFO] No command-line options provided, building default streamline-image"
    TAG="latest"
else
    echo "[INFO] Building streamline-image with tag: $1"
    TAG=$1
fi

docker build -t "streamline:$TAG" "$DIR"
