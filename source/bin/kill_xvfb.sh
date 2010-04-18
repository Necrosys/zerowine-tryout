#!/bin/sh

# SIGHUP Xvfb
ps -edf | grep ^$USER | grep "Xvfb :$1" | grep -v grep | awk '{ print $2 }' | xargs kill -15 && echo "Xvfb Killed"
