#!/bin/bash

# path to unzipped ISCX VPN-NonVPN pcaps
pcaps=$1
# path to write data and index files
outdir=$2

ls $pcaps/*.pcap > $outdir/pcaps.txt

mkdir $outdir/data

for pcap in `cat $outdir/pcaps.txt` ; do
    echo python3 scripts/pcap2corpus.py -M 1 $pcap $outdir/data
    python3 scripts/pcap2corpus.py -M 1 $pcap $outdir/data
done

cat $outdir/data/*.scp > $outdir/full.scp

# use our pre-defined partitions wth labels
cat $outdir/full.scp | perl scripts/filter_scp.pl resources/train.key | sort -R > $outdir/train.scp
cat $outdir/full.scp | perl scripts/filter_scp.pl resources/test.key | sort -R > $outdir/test.scp
cat $outdir/full.scp | perl scripts/filter_scp.pl resources/valid.key | sort -R > $outdir/valid.scp

