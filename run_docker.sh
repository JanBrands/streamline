#!/bin/bash

DIR="$(dirname "$(readlink -f "$0")")"
IMAGE="latest"
targets_dir=""
cmd=""

function usage {
    echo "[*] Usage: $0 [-t <tag>] <targets_dir> [<cmd>]"
    echo "      -t <tag>        Use streamline-image with tag: <tag>"
    echo "      <targets_dir>   Directory containing target projects"
    echo "      <cmd>           Command to be executed in the container"
}

while [[ $# -gt 0 ]]; do
    case $1 in
    -h)
        usage
        exit 0
        ;;
    -t)
        shift
        IMAGE="$1"
        echo "[*] Using streamline-image with tag: $IMAGE"
        shift
        ;;
    *)
        targets_dir="$1"
        shift
        while [ "$1" ]; do
            cmd="$cmd $1"
            shift
        done
        ;;
    esac
done

if [ -z "$targets_dir" ]; then
    echo "[!] No <targets_dir> specified"
    usage
    exit 1
fi

if [[ ! -d "$targets_dir" ]]; then
    echo "[!] Directory '$targets_dir' does not exist"
    exit 1
fi

if [ -z "$cmd" ]; then
    cmd="/bin/bash"
    echo "[*] No <cmd> specified. Defaulting to '$cmd'"
fi

echo "[+] Mapping local directory '$targets_dir' into container"
echo "[+] Executing command: '$cmd'"

if [ -t 0 ]; then
    docker_options="-i"
else
    docker_options="-it"
fi

echo "[+] Running docker with '$docker_options'"

docker run \
    "$docker_options" \
    --mount type=bind,source="$(realpath $targets_dir)",target=/home/user/targets \
    "streamline:$IMAGE" $cmd
