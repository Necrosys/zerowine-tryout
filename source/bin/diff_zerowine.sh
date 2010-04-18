#!/bin/sh

diff -qr -x harddiskvolume0 -x dosdevices -x globalroot -x SystemRoot $2 $1 | grep -v '(null)' | sed 's/\(Only in \|Files \)//g;s/: /\//g;s/ and \/.*//g;s/.*Documents and Settings.*//g;/^$/d' | xargs -i cp --parents -a {} $3
diff -qr -x harddiskvolume0 -x dosdevices -x globalroot -x SystemRoot $2 $1 | grep -v '(null)' | sed 's/\(Only in \|Files \)//g;s/: /\//g;s/ and \/.*//g;s/.*Documents and Settings.*//g;/^$/d' > $3/../diff.list.txt
cat $3/../diff.list.txt | xargs -i md5sum {} > $3/../diff.hashes.md5.txt
cat $3/../diff.list.txt | xargs -i shasum -a 1 {} > $3/../diff.hashes.sha1.txt
cat $3/../diff.list.txt | xargs -i shasum -a 224 {} > $3/../diff.hashes.sha224.txt
cat $3/../diff.list.txt | xargs -i shasum -a 256 {} > $3/../diff.hashes.sha256.txt
cat $3/../diff.list.txt | xargs -i shasum -a 384 {} > $3/../diff.hashes.sha384.txt
cat $3/../diff.list.txt | xargs -i shasum -a 512 {} > $3/../diff.hashes.sha512.txt
diff -r -U 0 -x harddiskvolume0 -x drive_c -x drive_d -x globalroot -x SystemRoot $1 $2 | grep -v '(null)' | sed 's/.*dosdevices\///g;s/\(Only in \|Files \)//g;s/: /\//g;s/ and \/.*//g;s/.*Documents and Settings.*//g;s/diff -r -U.*//g'
