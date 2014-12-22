#!/bin/bash - 
#===============================================================================
#
#          FILE: test.sh
# 
#         USAGE: ./test.sh 
# 
#   DESCRIPTION: 
# 
#       OPTIONS: ---
#  REQUIREMENTS: ---
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: BOSS14420 (), 
#  ORGANIZATION: 
#       CREATED: 09/09/2014 08:34
#      REVISION:  ---
#===============================================================================

set -o nounset                              # Treat unset variables as an error

SCSR_HOME="$(dirname $0)"
ENCRYPT="$SCSR_HOME/encrypt"
DECRYPT="$SCSR_HOME/decrypt"

keysize=6144

keydir="keys/"
publickey="$keydir/tmpkey.publickey"
secretkey="$keydir/tmpkey.secretkey"

if [ ! -f $publickey ]; then
    echo "Generating rsa key ..."
    mkdir -p $keydir
    cd $keydir
    $SCSR_HOME/rsa_genkey $keysize tmpkey
    ln $publickey admin.publickey
    ln $secretkey admin.secretkey
    cd -
    echo "Done"
fi

outdir=/tmp/secureshare
mkdir -p $outdir

python2 -c "print '|' + '-'*17 + '|' + '-'*12 + '|' + '-'*10 + \
                '|' + '-'*11 + '|' + '-'*15 + '|' + '-'*10 + '|' + '-'*9 + '|'"
printf "| %-15s | %-10s | %-8s | %-9s | %-13s | %-8s | %-6s |\n" \
    "File" "Dung lượng" "File mã " "Tỉ lệ    " "Thời gian    " "Giải mã " "K/t MD5"
python2 -c "print '|' + '-'*17 + '|' + '-'*12 + '|' + '-'*10 + \
                '|' + '-'*11 + '|' + '-'*15 + '|' + '-'*10 + '|' + '-'*9 + '|'"

for file in "$@"
do
    filename=$(basename "$file")
    encfile="$outdir/$filename.enc"
    decfile="$outdir/$filename.dec"
    hsz=$(/bin/ls -lh "$file" | cut -d" " -f5)iB
    printf "| %-15s | %-10s |" "$filename" $hsz

    ctime=$(/usr/bin/time -f "%e" $ENCRYPT "$file" "$encfile" -d "$keydir" tmpkey 2>&1)
    hcsz=$(/bin/ls -lh "$encfile" | cut -d" " -f5)iB
    sz=$(stat --printf "%s" "$file")
    csz=$(stat --printf "%s" "$encfile")
    ratio=$(echo "$csz / $sz" | bc -l)
    ratio=$(printf "%.03f" $ratio)
    printf " %-8s | %-09s | %-13s |" $hcsz $ratio "$ctime"s

    xtime=$(/usr/bin/time -f "%e" $DECRYPT "$encfile" "$decfile" tmpkey $secretkey 2>&1)
    printf " %-8s |" "$xtime"s
    #printf "| %-15s | %-10s | %-8s | %-09s | %-13s | %-8s |\n" \
    #    "$filename" $hsz $hcsz $ratio "$ctime"s "$xtime"s

    md51=$(md5sum "$file" | cut -d" " -f1)
    md52=$(md5sum "$decfile" | cut -d" " -f1)
    if [[ $md51 != $md52 ]]; then
        printf " %-7s |\n" "Lỗi"
    else
        printf " %-7s |\n" "OK"
        rm "$encfile" "$decfile"
    fi
done

python2 -c "print '|' + '-'*17 + '|' + '-'*12 + '|' + '-'*10 + \
                '|' + '-'*11 + '|' + '-'*15 + '|' + '-'*10 + '|' + '-'*9 + '|'"
