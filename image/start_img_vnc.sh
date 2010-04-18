#!/bin/sh

qemu -hda zerowine.img -boot c -m 1024 -redir tcp:8000::8000 -redir tcp:2022::22 -vnc :1

