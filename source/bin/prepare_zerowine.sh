#!/bin/sh

umask 0022
echo "Cleaning previous files ... "
rm -fr $1/*
chmod -R ug+w $1
cd $1
tar -xvzf /home/malware/backup/backup.tar.gz
