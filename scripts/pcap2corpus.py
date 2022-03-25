#!/usr/bin/env python3
"""
Pcap2Corpus

Extract packets by flow from ICSX VPN-NONVPN data files.
storing in indexed HDFS-5 (.h5) files, andd labeled with 
flow category for model training.

"""
import ijson
import json
import sys
import argparse
import os
import numpy as np
import h5py


"""                                                                                                                     
Get the payload bytes in the packet                                                                                     
                                                                                                                        
@param packet - packet                                                                                                  
                                                                                                                        
@return the payload bytes                                                                                               
"""
def payload_bytes(packet) :
    if "tcp" in packet["layers"] :
        return int(packet["layers"]["tcp"]["tcp.len"])
    elif "udp" in packet["layers"] :
        return int(packet["layers"]["udp"]["udp.length"])-8
    else :
        return 0

"""                                                                                                                     
Get the bytes in the packet                                                                                             
                                                                                                                        
@param packet - packet                                                                                                  
                                                                                                                        
@return the byte string                                                                                                 
"""
def get_bytes(packet, header=True) :
    if "frame_raw" not in packet["layers"] :
        return ""

    if header :
        bstr = packet["layers"]["frame_raw"][0]
    else :
        if "tcp_raw" in packet["layers"] :
            hlen = int(packet["layers"]["tcp"]["tcp.hdr_len"])
            if "tcp.payload_raw" in packet["layers"]["tcp"] :
                bstr = packet["layers"]["tcp"]["tcp.payload_raw"][0]
            else :
                bstr = ""
        elif "udp_raw" in packet["layers"] :
            udplen=payload_bytes(packet)*2
            bstr = packet["layers"]["frame_raw"][0][-udplen:]
            if len(bstr) == 0 :
                bstr = ""
        else :
            bstr = ""

    return bstr


""" 
Flow helper class

This class represents a flow object comprising of multiple packets
and specialized metadata
"""
class Flow :
    """
    Constructor

    @param flowid - id for given flow
    @param startts - starting time stamp, measured in nanos
    @param payload - packet payload
    @param srcip - source ip
    @param idx - index
    """
    def __init__(self, flowid, startts, payload, srcip, idx=0) :
        self.flowid = flowid
        self.start = startts
        self.timestamps = []
        self.timestamps.append(startts)

        self.flowLastSeen=startts

        self.forwardBytes = 0
        self.backwardBytes = 0

        self.forward = []
        self.backward = []
        self.first_index = idx
        self.last_index = idx
        
        self.src = srcip
        self.packets = []
        self.max_pktlen = 0

        if self.is_forward(srcip) :
            self.forward.append(startts)
            self.forwardLastSeen = startts;
            self.forwardBytes = payload_bytes(payload)
        else:
            self.backward.append(startts)
            self.backwardLastSeen = startts;
            self.backwardBytes = payload_bytes(payload)

    """
    Checks if the flow is forward or backwards (sent or recieved)

    @param srcip - source ip

    @returns boolean of check
    """
    def is_forward(self, srcip) :
        return self.src == srcip

    """
    Calculates duration of flow

    @return duration
    """
    def duration(self) :
        return self.timestamps[-1]-self.timestamps[0]

    """
    Calculates the packet count based on direction or timestamps

    @param feat - current flow feat

    @return packet count
    """
    def packet_count(self) :
        return len(self.timestamps)


    """
    Adds packet to flow

    @param timestamp - timestamp of packet
    @param payload - payload of packet
    @param fwd - boolean if packet is foward
    @param pktheader - boolean if packet has header
    """
    def add_packet(self, timestamp, payload, fwd = True, pktheader=True) :
        currentTimestamp = timestamp
        if fwd :
            self.forward.append(timestamp)
            self.forwardBytes+=payload_bytes(payload)
            self.forwardLastSeen = currentTimestamp;
        else :
            self.backward.append(timestamp)
            self.backwardBytes+=payload_bytes(payload)
            self.backwardLastSeen = currentTimestamp;

        pkt = get_bytes(payload, header=pktheader)

        self.packets.append(pkt)
        if len(pkt) > self.max_pktlen :
            self.max_pktlen = len(pkt)

        self.flowLastSeen = timestamp
        self.timestamps.append(timestamp)
        

            
    """
    Converts the flow into matrix form

    @return flow as matrix
    """
    def as_matrix(self) :
        # NOTE: kaldi io only accepts float32, which blows up the file size  
        pmat = np.zeros((len(self.packets), int(self.max_pktlen/2)+2), dtype=np.uint8)

        for (i,pkt) in enumerate(self.packets) :
            (a,b) = lenbytes(len(pkt)/2)
            #sys.stderr.write(self.flowid+ " " + str((a,b)) + " " + str(len(pkt)) + "\n")
            pmat[i][0] = a 
            pmat[i][1] = b
            for j in range(0, len(pkt), 2) :
               pmat[i][int(j/2)+2] = int(pkt[j:j+2], 16)
                
        #sys.stderr.write("PACKET " + str(pmat.shape) + "\n")
        return pmat

"""
Calculates the length of the bytes

@return float, int
"""
def lenbytes(x) :
    b = x % 256
    a = int(x/256)
    return (a,b)



"""
Checks packet for FIN flag

@return boolean based on flag
"""
def has_flag_FIN(packet) :
    if "tcp" in packet["layers"] :
        if "tcp.flags.fin" in packet["layers"]["tcp"] :
            if int(packet["layers"]["tcp"]["tcp.flags.fin"]) == 1 :
                return True
        if "tcp.flags_tree" in packet["layers"]["tcp"]:
            if "tcp.flags.fin" in packet["layers"]["tcp"]["tcp.flags_tree"] :
                if int(packet["layers"]["tcp"]["tcp.flags_tree"]["tcp.flags.fin"]) == 1 :
                    return True
    return False

"""
Updates features for flow based on current packet

@param docid - current docid
@param payload - current payload
@param currentFlows -  array of current flows
@param srcip - source ip
@param mincount - minimum count for packets in flow
@param label - category label associated with flow
@param pidx - packet index in PCAP
@param fname - file name for purli
@param datafd - various objects for file writing
@param pktheader - packet header
"""
def update_feats(docid, payload, currentFlows, srcip=None, mincount=2, 
                 pidx=0, datafds = None, pktheader=True) :

    timestamp = int(float(payload["layers"]["frame"]["frame.time_epoch"])*1000000)

    assert(datafds is not None and len(datafds) == 3)
    (ark, scp, arkfn) = datafds

    if docid in currentFlows :
        flow = currentFlows[docid]
        fwd = flow.is_forward(srcip)

        # group all packets from this purli into a single flow
        flow.add_packet(timestamp, payload, fwd=fwd, pktheader=pktheader);
        flow.last_index = pidx
    else :
        currentFlows[docid] = Flow(docid, timestamp, payload, srcip, idx=pidx)


"""
Checks to see which ip is greater for purli formatting

@param ipa - first ip
@param ipb - second ip
@param p - check for ipv6

@return boolean based on result
"""
def ip_greater(ipa, ipb, p) :
    if p == "ipv6" :
        return ipa > ipb

    a = [int(x) for x in ipa.split(".")]
    b = [int(x) for x in ipb.split(".")]
    for (i,x) in enumerate(a) :
        if a[i] != b[i] :
            return a[i] > b[i]
    return False


"""
Writes flow out to various files

@param flow - current flow
@param mincount - minimum count for packets in flow
@param datafd - various objects for file writing

"""
def write_flow(flow,  mincount=2, datafds=None) :

    docid = flow.flowid
    
    assert( datafds is not None and len(datafds) == 3)
    (ark, scp, arkfn) = datafds

    if flow.packet_count() < mincount:
        return

    arkidx = "p%d" % (flow.first_index)
    scp.write("%s-%07d %s:%s\n" % (flow.flowid, flow.first_index, os.path.abspath(arkfn), arkidx))
    ark.create_dataset(arkidx, data=flow.as_matrix())


""" Main CLI method """
def main():
    parser = argparse.ArgumentParser(
        description='Project description', 
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    

    parser.add_argument('-M', '--min-count', type=int, default=1)
    parser.add_argument('-P', '--payload-only', action="store_true")

    parser.add_argument('pcap', type=str, help='feature file path')
    parser.add_argument('datadir', type=str)
    
    args = parser.parse_args()

    file = args.pcap

    # 
    pktheader=(args.payload_only==False)

    filename = os.path.basename(os.path.splitext(file)[0]) #original pcap filename

    arkfn = args.datadir + "/" + filename + ".h5"
    ark = h5py.File(arkfn, "w")
    scp = open(args.datadir + "/" + filename + ".scp", "w")
    optargs=" -x "

    # attempt conversion
    try:
        result = os.popen("tshark -r " + file + optargs + " -T json --disable-protocol ssl")
    except:
        print("Conversion was not successful")
        return

    current = {}

    # iterate through objects
    pidx = -1
    for obj in ijson.items(result, 'item'):
        pidx += 1
        packet = obj['_source']

        timestamp = float(packet["layers"]["frame"]["frame.time_epoch"])

        if "ip" in packet["layers"] or "ipv6" in packet["layers"]:
            if "ip" in packet["layers"] :
                p = "ip"
            else :
                p = "ipv6"

            frame = packet["layers"][p]
            src = frame[p + ".src"]
            dst = frame[p + ".dst"]
            
            # check transport
            if "udp" in packet["layers"] :
                udp = packet["layers"]["udp"]
                ipdata = udp
                transport = "udp"
                src_port = udp["udp.srcport"]
                dst_port = udp["udp.dstport"]
            elif "tcp" in packet["layers"] :
                tcp = packet["layers"]["tcp"]
                ipdata = tcp
                transport = "tcp"
                src_port = tcp["tcp.srcport"]
                dst_port = tcp["tcp.dstport"]
            elif "sctp" in packet["layers"] :
                tcp = packet["layers"]["sctp"]
                ipdata = tcp
                transport = "sctp"
                src_port = tcp["sctp.srcport"]
                dst_port = tcp["sctp.dstport"]
            elif "icmp" in packet["layers"] :
                if "udp" in packet["layers"]["icmp"] :
                    udp = packet["layers"]["icmp"]["udp"]
                    ipdata = udp
                    transport = "udp"
                    src_port = udp["udp.srcport"]
                    dst_port = udp["udp.dstport"]
                elif "tcp" in packet["layers"]["icmp"] :
                    tcp = packet["layers"]["icmp"]["tcp"]
                    ipdata = tcp
                    transport = "tcp"
                    src_port = tcp["tcp.srcport"]
                    dst_port = tcp["tcp.dstport"]
                else :
                    sys.stderr.write(str(list(packet["layers"]["icmp"])) + "\n")
                    continue
                continue
            else :
                continue

            fwd =True
            

            if "l2tp" in packet["layers"] :
                transport="l2tp"

            fwd = True
            if ip_greater(src, dst, p) :
                fwd = False
                docid = "%s-%s-%s-%s-%s" % (dst, src, dst_port, src_port, transport)
            else:
                docid = "%s-%s-%s-%s-%s" % (src, dst, src_port, dst_port, transport)
                fwd = True

            update_feats(docid, packet, current, srcip=src, mincount=args.min_count, 
                         pidx=pidx,  datafds=(ark,scp,arkfn), pktheader=pktheader)
        else :
            sys.stderr.write(str(list(packet["layers"])) + "\n")

    for docid in current :
        write_flow(current[docid], mincount=args.min_count, datafds=(ark, scp, arkfn))

if __name__ == '__main__':
    main()
