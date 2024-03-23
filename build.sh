#!/usr/bin/env bash

cd "$(dirname "$0")"

docker run --rm -v .:/home/rust -w /home/rust rust:1.77 cargo build --release