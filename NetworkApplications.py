import argparse
import socket
import os
import sys
import struct
import time
import random
import traceback
import threading


UDP_CODE = socket.IPPROTO_UDP
ICMP_ECHO_REQUEST = 8
MAX_DATA_RECV = 65535
MAX_TTL = 30

def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications')
        parser.set_defaults(func=ICMPPing, hostname='google.com')
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
        parser_p.set_defaults(timeout=2, count=10)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                         help='run traceroute')
        parser_t.set_defaults(timeout=2, protocol='udp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)
        
        parser_m = subparsers.add_parser('mtroute', aliases=['mt'],
                                         help='run traceroute')
        parser_m.set_defaults(timeout=2, protocol='udp')
        parser_m.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_m.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_m.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_m.set_defaults(func=MultiThreadedTraceRoute)

        parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
        parser_w.set_defaults(port=8080)
        parser_w.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_w.set_defaults(func=WebServer)

        parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
        parser_x.set_defaults(port=8000)
        parser_x.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_x.set_defaults(func=Proxy)

        if len(sys.argv) < 2:
            parser.print_help()
            sys.exit(1)

        args = parser.parse_args()

        return args


class NetworkApplication:

    def checksum(self, dataToChecksum: bytes) -> int: 
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = dataToChecksum[count+1] * 256 + dataToChecksum[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer

    # Print Ping output
    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, seq: int, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%.3f ms" % (packetLength, destinationHostname, destinationAddress, seq, ttl, time))
        else:
            print("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms" % (packetLength, destinationAddress, seq, ttl, time))

    def printAdditionalDetails(self, host, numPacketsTransmitted, rtts):
        if len(rtts) > 0:
            print(f'--- {host} ping statistics ---')
            lossPercent = int((100.0 - 100.0*(len(rtts)/numPacketsTransmitted)))
            print(f'{numPacketsTransmitted} packets transmitted, {len(rtts)} received, {lossPercent}% packet loss')
            avgRTT = sum(rtts) / len(rtts)
            deviations = [abs(rtt - avgRTT) for rtt in rtts]
            mdev = sum(deviations) / len(deviations)
            minRTT = min(rtts)
            maxRTT = max(rtts)
            print("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms" % (1000*minRTT, 1000*avgRTT, 1000*maxRTT, 1000*mdev))

    # Print one line of traceroute output
    def printMultipleResults(self, ttl: int, pkt_keys: list, hop_addrs: dict, rtts: dict, destinationHostname = ''):
        if pkt_keys is None:
            print(str(ttl) + '   * * *')
            return
        # Sort packet keys (sequence numbers or UDP ports)
        pkt_keys = sorted(pkt_keys)
        output = str(ttl) + '   '
        last_hop_addr = None
        last_hop_name = None

        for pkt_key in pkt_keys:
            # If packet key is missing in hop addresses, this means no response received: print '*'
            if pkt_key not in hop_addrs.keys():
                output += '* '
                continue
            hop_addr = hop_addrs[pkt_key]

            # Get the RTT for the probe
            rtt = rtts[pkt_key]
            if last_hop_addr is None or hop_addr != last_hop_addr:
                hostName = None
                try:
                    # Get the hostname for the hop
                    hostName = socket.gethostbyaddr(hop_addr)[0]
                    if last_hop_addr is None:
                        output += hostName + ' '
                    else: 
                        output += ' ' + hostName + ' '
                except socket.herror:
                    output += hop_addr + ' '
                last_hop_addr = hop_addr
                last_hop_name = hostName
                output += '(' + hop_addr + ') '

            output += str(round(1000*rtt, 3))
            output += ' ms  '
                
        print(output)           

class ICMPPing(NetworkApplication):
    
    def __init__(self, args):
        host = None
        # 1. Look up hostname, resolving it to an IP address
        try:
            host = socket.gethostbyname(args.hostname)
        except socket.gaierror:
            print('Invalid hostname: ', args.hostname) 
            return

        print('Ping to: %s (%s)...' % (args.hostname, host))

        # 1. Create an ICMP socket 
        try:
            self.icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except socket.error as err:
            traceback.print_exception(err)
            exit(1)

        # 2. Set a timeout on the socket
        self.icmpSocket.settimeout(args.timeout)

        # 3. Send ping probes and collect responses 
        numPings = args.count
        seq_num = 0
        numPingsSent = numPings
        rtts = [] 
        while(numPings > 0):

            # 4. Do one ping approximately every second
            rtt, ttl, packetSize, seq = self.doOnePing(host, args.timeout, seq_num)

            # 5. Print out the RTT (and other relevant details) using the printOneResult method
            if rtt is not None:
                self.printOneResult(host, packetSize, rtt*1000, seq, ttl) 
                rtts.append(rtt)

            # 6. Sleep for a second
            time.sleep(1) 

            # 7. Update sequence number and number of pings
            seq_num += 1
            numPings -= 1

        # 8. Print loss and RTT statistics (average, max, min, etc.)
        self.printAdditionalDetails(args.hostname, numPingsSent, rtts)
        
        # 9. Close ICMP socket
        self.icmpSocket.close()

    # Receive Echo ping reply
    def receiveOnePing(self, destinationAddress, packetID, sequenceNumSent, timeout):
        
        # 1. Wait for the socket to receive a reply
        echoReplyPacket = None
        isTimedout = False
        try:
            echoReplyPacket, addr = self.icmpSocket.recvfrom(MAX_DATA_RECV)
        except socket.timeout as e:
            isTimedout = True

        # 2. Once received, record time of receipt, otherwise, handle a timeout
        timeRecvd = time.time()
        if isTimedout: # timeout
            return None, None, None, None

        # 3. Extract the IP header: 

        ip_header = echoReplyPacket[:20]
        version_ihl, tos, total_length, identification, flags_offset, ttl, proto, checksum, src_ip, dest_ip = struct.unpack('!BBHHHBBH4s4s', ip_header)

        # Read the IP Header Length (using bit masking) 
        ip_header_len_field = (version_ihl & 0x0F)

        # This field contains the length of the IP header
        ip_header_len = ip_header_len_field * 4

        payloadSize = total_length - ip_header_len 
        icmpHeader = echoReplyPacket[ip_header_len:ip_header_len + 8]
        icmpType, code, checksum, p_id, sequenceNumReceived = struct.unpack('!BBHHH', icmpHeader)

        # 5. Check that the ID and sequence numbers match between the request and reply
        if packetID != p_id or sequenceNumReceived != sequenceNumSent:
            return None, None, None, None

        # 6. Return the time of Receipt
        return timeRecvd, ttl, payloadSize, sequenceNumReceived

    # NOTE: This method can be re-used by ICMP traceroute
    # Send Echo Ping Request
    def sendOnePing(self, destinationAddress, packetID, sequenceNumber, ttl=None, dataLength=0):
        # 1. Build ICMP header
        header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, 0, packetID, sequenceNumber)
        
        # 2. Checksum ICMP packet using given function
        # include some bytes 'AAA...' in the data (payload) of ping
        data = str.encode(dataLength * 'A')
        my_checksum = self.checksum(header+data)

        # 3. Insert checksum into packet
        packet = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), packetID, sequenceNumber)

        if ttl is not None:
            self.icmpSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

        # 4. Send packet using socket
        self.icmpSocket.sendto(packet+data, (destinationAddress, 1))

        # 5. Record time of sending (state)
        timeSent = time.time()
        return timeSent

    def doOnePing(self, destinationAddress, timeout, seq_num):

        # 3. Call sendOnePing function
        packetID = random.randint(1, 65535)
        timeSent = self.sendOnePing(destinationAddress, packetID, seq_num, dataLength=48)

        # 4. Call receiveOnePing function
        timeReceipt, ttl, packetSize, seq = self.receiveOnePing(destinationAddress, packetID, seq_num, timeout)

        # 5. Compute RTT
        rtt = None
        if timeReceipt is None:
            print("Error receiveOnePing() has timed out")
        else:
            rtt = timeReceipt - timeSent

        # 6. Return total network delay, ttl, size and sequence number
        return rtt, ttl, packetSize, seq

class Traceroute(ICMPPing):

    def __init__(self, args):
        args.protocol = args.protocol.lower()

        # 1. Look up hostname, resolving it to an IP address
        self.dstAddress = None
        try:
            self.dstAddress = socket.gethostbyname(args.hostname)
            #socket.getaddrinfo(args.hostname, None, socket.AF_INET6)
        except socket.gaierror:
            print('Invalid hostname: ', args.hostname) 
            return
        print('%s traceroute to: %s (%s) ...' % (args.protocol, args.hostname, self.dstAddress))

        # 2. Initialise instance variables
        self.isDestinationReached = False

        # 3. Create a raw socket bound to ICMP protocol
        self.icmpSocket = None
        try:
            self.icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except socket.error as err:
            traceback.print_exception(err)
            exit(1)

        # 4. Set a timeout on the socket
        self.icmpSocket.settimeout(args.timeout)

        # 5. Run traceroute
        self.runTraceroute()

        # 6. Close ICMP socket
        self.icmpSocket.close()

    def runTraceroute(self):

        hopAddr = None
        pkt_keys = []
        hop_addrs = dict()
        rtts = dict()
        ttl = 1

        while(ttl <= MAX_TTL and self.isDestinationReached == False):
            if args.protocol == "icmp":
                self.sendIcmpProbesAndCollectResponses(ttl)

            elif args.protocol == "udp":
                self.sendUdpProbesAndCollectResponses(ttl)
            else:
                print(f"Error: invalid protocol {args.protocol}. Use udp or icmp")
                sys.exit(1)
            ttl += 1

    # Send 3 ICMP traceroute probes per TTL and collect responses
    def sendIcmpProbesAndCollectResponses(self, ttl):
        
        # init data structures
        pkt_keys = []
        hop_addrs = dict()
        rtts = dict()

        # Send 3 ICMP probes
        for _ in range(3):  
            # 1. Send ICMP ping
            packetID = random.randint(1, 65535)  
            timeSent = self.sendOnePing(self.dstAddress, packetID, _, ttl=ttl)

            # 2. Use _ as key for tracking probe
            pkt_keys.append(_)

            # 3. Receive response
            trReplyPacket, hopAddr, timeReceived = self.receiveOneTraceRouteResponse()
        
            # Skip to next probe if there is no response
            if trReplyPacket is None:
                continue

            # 4. Parse the ICMP response
            probe_num, icmp_type, reciv_packetID = self.parseICMPTracerouteResponse(trReplyPacket)

            # 5. Check if this is the final dest
            if self.dstAddress == hopAddr and icmp_type == 0:
                self.isDestinationReached = True

            # 6. Log the RTT and hop address
            rtts[_] = timeReceived - timeSent
            hop_addrs[_] = hopAddr

        self.printMultipleResults(ttl, pkt_keys, hop_addrs, rtts, args.hostname)
            

    # Send 3 UDP traceroute probes per TTL and collect responses
    def sendUdpProbesAndCollectResponses(self, ttl):
        
        hopAddr = None
        icmpType = None
        pkt_keys = []
        hop_addrs = dict()
        rtts = dict()

        numBytes = 52
        dstPort = 33439
        
        for _ in range(3): 
            # 1. Send one UDP traceroute probe
            dstPort += 1
            timeSent = self.sendOneUdpProbe(self.dstAddress, dstPort , ttl, numBytes)

            # 2. Record a unique key (UDP destination port) associated with the probe
            pkt_keys.append(dstPort)

            # 3. Receive the response (if one arrives within the timeout)
            trReplyPacket, hopAddr, timeRecievd = self.receiveOneTraceRouteResponse()
            if trReplyPacket is None:
                # Nothing is received within the timeout period
                continue
            
            # 4. Extract destination port from the reply
            dstPortReceived, icmpType = self.parseUDPTracerouteResponse(trReplyPacket)
        
            # 5. Check if we reached the destination 
            if self.dstAddress == hopAddr and icmpType == 3:
                self.isDestinationReached = True

            # 6. If the response matches the request, record the rtt and the hop address
            if dstPort == dstPortReceived:
                rtts[dstPort] = timeRecievd - timeSent
                hop_addrs[dstPort] = hopAddr

        # 7. Print one line of the results for the 3 probes
        self.printMultipleResults(ttl, pkt_keys, hop_addrs, rtts, args.hostname)

    # Parse the response to UDP probe 
    def parseUDPTracerouteResponse(self, trReplyPacket):

        # 1. Parse the IP header
        dst_port = None
        # Extract the first 20 bytes 
        ip_header = struct.unpack("!BBHHHBBH4s4s", trReplyPacket[:20])

        # 2. Read the IP Header Length (using bit masking) 
        ip_header_len_field = (ip_header[0] & 0x0F)

        # 3. Compute the IP header length
        # This field contains the length of the IP header
        ip_header_len = ip_header_len_field * 4
        
        # 4. Parse the outermost ICMP header which is 8 bytes long:
        icmpType, _, _, _, _  = struct.unpack("!BBHHH", trReplyPacket[ip_header_len:ip_header_len + 8])
        
        # 5. Parse the ICMP message if it has the expected type
        if icmpType == 3 or icmpType == 11:
            ip_header_inner = struct.unpack("!BBHHHBBH4s4s", trReplyPacket[ip_header_len + 8:ip_header_len+28])

            # This is the original IP header sent in the probe packet
            ip_header_len_field = (ip_header_inner[0] & 0x0F)
            ip_header_inner_len = ip_header_len_field * 4
            
            # Extract the destination port and match using source port (UDP)
            _, dst_port, _, _ = struct.unpack('!HHHH', trReplyPacket[ip_header_len + 8 + ip_header_inner_len : ip_header_len + 8 + ip_header_inner_len + 8])

        return dst_port, icmpType
    
    def parseICMPTracerouteResponse(self, trReplyPacket):
        try:
            # Parse outer IP header (first 20 bytes)
            ip_header = struct.unpack("!BBHHHBBH4s4s", trReplyPacket[:20])

            # Extract IP header len
            ip_header_len_field = (ip_header[0] & 0x0F)
            ip_header_len = ip_header_len_field * 4
            
            # check for minimum IP header size
            if ip_header_len < 20:
                print("Error: IP header length is too small.")
                return None, None, None

            # Parse the ICMP header
            icmp_header_start = ip_header_len
            icmp_header = struct.unpack("!BBHHH", trReplyPacket[icmp_header_start:icmp_header_start + 8])
            icmp_type, _, _, packetID, probe_num = icmp_header

            # check for type 11 for embedded IP header
            if icmp_type == 11:
                embedded_ip_start = ip_header_len + 8
                embedded_ip_header = struct.unpack("!BBHHHBBH4s4s", trReplyPacket[embedded_ip_start:embedded_ip_start + 20])

                # Extract the length of the embedded IP header
                embedded_ip_header_len = (embedded_ip_header[0] & 0x0F) * 4

                # Parse embedded ICMP header
                embedded_icmp_start = embedded_ip_start + embedded_ip_header_len
                embedded_icmp_header = struct.unpack("!BBHHH", trReplyPacket[embedded_icmp_start:embedded_icmp_start + 8])

                # Extract probe number and packet ID from the embedded ICMP header
                _, _, _, packetID, probe_num = embedded_icmp_header

            # Return the parsed values
            return probe_num, icmp_type, packetID

        except struct.error as error:
            print(f"Error unpacking packet: {error}")
            return None, None, None

    def receiveOneTraceRouteResponse(self):

        timeReceipt = None
        hopAddr = None
        pkt = None

        # 1. Receive one packet or timeout
        try:
            pkt, addr = self.icmpSocket.recvfrom(MAX_DATA_RECV)
            timeReceipt = time.time()
            hopAddr = addr[0]
        
        # 2. Handler for timeout on receive
        except socket.timeout as e:
            timeReceipt = None

        # 3. Return the packet, hop address and the time of receipt
        return pkt, hopAddr, timeReceipt

    def sendOneUdpProbe(self, destAddress, port, ttl, dataLength):

        # 1. Create a UDP socket
        udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, UDP_CODE)

        # 2. Use a socket option to set the TTL in the IP header
        udpSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

        # 3. Send the UDP traceroute probe
        udpSocket.sendto(str.encode(dataLength * '0'), (destAddress, port))

        # 4. Record the time of sending
        timeSent = time.time()

        # 5. Close the UDP socket
        udpSocket.close()

        return timeSent

class MultiThreadedTraceRoute(Traceroute):

    def __init__(self, args):
        # 1. Initialise instance variables (add others if needed)
        args.protocol = args.protocol.lower()
        self.timeout = args.timeout
        self.send_complete = threading.Event()
        self.pkt_keys = []
        self.probes = dict()

        self.dstAddress = None
        try:
            self.dstAddress = socket.gethostbyname(args.hostname)
            #socket.getaddrinfo(args.hostname, None, socket.AF_INET6)
        except socket.gaierror:
            print('Invalid hostname: ', args.hostname) 
            return
        print('%s mtraceroute to: %s (%s) ...' % (args.protocol, args.hostname, self.dstAddress))

        # Initialise instance variables
        self.isDestinationReached = False

        # Create a raw socket bound to ICMP protocol
        self.icmpSocket = None
        try:
            self.icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except socket.error as err:
            traceback.print_exception(err)
            exit(1)

        # Set a timeout on the socket
        self.icmpSocket.settimeout(args.timeout)
        
        # NOTE you must use a lock when accessing data shared between the two threads
        self.lock = threading.Lock()  

        # 2. Create a thread to send probes
        self.send_thread = threading.Thread(target=self.send_probes)

        # 3. Create a thread to receive responses 
        self.recv_thread = threading.Thread(target=self.receive_responses)

        # 4. Start the threads
        self.send_thread.start()
        self.recv_thread.start()

        # 5. Wait until both threads are finished executing
        self.send_thread.join()
        self.recv_thread.join()
        self.icmpSocket.close()
        
            
    # Thread to send probes (to be implemented, a skeleton is provided)
    def send_probes(self):

        ttl = 1
        while ttl <= MAX_TTL:
            
            if self.send_complete.is_set():
                break
            
            numBytes = 52
            dstPort = 33439
            
            # Send three probes per TTL
            for probe_num in range(3):  
                if args.protocol == "icmp":
                          
                    packetID = random.randint(1, 65535)
                    
                    timeSent = self.sendOnePing(self.dstAddress, packetID, probe_num, ttl=ttl)
                    
                    with self.lock:
                        self.probes[(packetID, probe_num)] = timeSent, ttl
                    
                elif args.protocol == "udp":
                    dstPort += 1
                    timeSent = self.sendOneUdpProbe(self.dstAddress, dstPort , ttl, numBytes)       
                    with self.lock:
                        self.probes[dstPort] = timeSent, ttl

                # Sleep for a short period between sending probes
                time.sleep(0.05)  # Small delay between probes
                
            print("ttl =", ttl)
            ttl += 1

        # A final sleep before notifying the receive thread to exit
        time.sleep(args.timeout)
        # Notify the other thread that sending is complete
        self.send_complete.set()    

    # Thread to receive responses (to be implemented, a skeleton is provided)
    def receive_responses(self):

        counter = 0
        rtts = dict()  
        hop_addrs = dict()
        pkt_keys = []
        seq_counter = 0
        # Keep receiving responses until notified by the other thread
        while not self.send_complete.is_set():

            if args.protocol == "icmp":
                      
                try:
                    trReplyPacket, hopAddr, timeReceived = self.receiveOneTraceRouteResponse()
                    
                    # Check if response is received
                    if trReplyPacket is None:
                        continue
                    
                    # Lock to access shared resources safely
                    with self.lock:
                        
                        probe_num, icmp_type, packetID = self.parseICMPTracerouteResponse(trReplyPacket)
                        # Check if probe response matches the sent probe to calculate RTT
                        for (sent_packetID, _), timeSent in self.probes.items():
                            if packetID == sent_packetID:
                                
                                # Record probe key, calculate RTT, log hop address
                                pkt_keys.append(probe_num)
                                
                                ttl = self.probes[(sent_packetID, probe_num)][1]
                                timeSent = self.probes[(sent_packetID, probe_num)][0]
                                
                                rtts[probe_num] = timeReceived - timeSent
                                hop_addrs[probe_num] = hopAddr
                                #increment sequence counter
                                seq_counter += 1
                            
                            if seq_counter == 3:
                                # Print the results for the 3 probes
                                self.printMultipleResults(ttl, pkt_keys, hop_addrs, rtts, args.hostname)
                                # Clear data structures for the next TTL
                                rtts = dict()  
                                hop_addrs = dict()
                                pkt_keys = []
                                seq_counter = 0
                                
                        # Check if the destination is reached for 3 probes
                        if hopAddr == self.dstAddress and icmp_type == 0:
                            counter += 1
                        if counter == 3:
                            self.isDestinationReached = True
                            # Stop sending of probes
                            self.send_complete.set()
                        
                except socket.timeout:
                    continue
                
            elif args.protocol == "udp":
                
                trReplyPacket, hopAddr, timeRecievd = self.receiveOneTraceRouteResponse()
                
                # Check if response is received
                if trReplyPacket is None:
                    continue
            
                with self.lock:  
                    dstPortReceived, icmp_type = self.parseUDPTracerouteResponse(trReplyPacket)
                    # Add dst port to the list of packet keys
                    pkt_keys.append(dstPortReceived)
                    # Check if the response matches the sent probe to calculate RTT
                    for (dstPort), timeSent in self.probes.items():
                        
                        if dstPortReceived == dstPort:
                            # Log ttl, hop address and calculate RTT
                            ttl = self.probes[dstPortReceived][1]
                            timeSent = self.probes[dstPortReceived][0]
                            rtts[dstPortReceived] = timeRecievd - timeSent
                            hop_addrs[dstPort] = hopAddr
                            # increment sequence counter
                            seq_counter += 1
                        
                        if seq_counter == 3:
                            # Print the results for the 3 probes
                            self.printMultipleResults(ttl, pkt_keys, hop_addrs, rtts, args.hostname)
                            # Clear data structures for the next TTL
                            rtts = dict()  
                            hop_addrs = dict()
                            pkt_keys = []
                            seq_counter = 0
                            
                    # Check if the destination is reached for 3 probes
                    if icmp_type == 3 and hopAddr == self.dstAddress:
                        counter += 1
                        print("counter =",counter)
                    if counter == 3:
                        self.isDestinationReached = True
                        self.send_complete.set()
    




# A basic multi-threaded web server implementation
class WebServer(NetworkApplication):

    def __init__(self, args):
        print('Web Server starting on port: %i...' % args.port)
        
        # 1. Create a TCP socket 
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # 2. Bind the TCP socket to server address and server port
        serverSocket.bind(("", args.port))
        
        # 3. Continuously listen for connections to server socket
        serverSocket.listen(100)
        print("Server listening on port", args.port)
        
        while True:
            # 4. Accept incoming connections
            connectionSocket, addr = serverSocket.accept()
            print(f"Connection established with {addr}")
            
            # 5. Create a new thread to handle each client request
            threading.Thread(target=self.handleRequest, args=(connectionSocket,)).start()

        # Close server socket (this would only happen if the loop was broken, which it isn't in this example)
        serverSocket.close()

    def handleRequest(self, connectionSocket):
        try:
            # 1. Receive request message from the client
            message = connectionSocket.recv(MAX_DATA_RECV).decode()

            # 2. Extract the path of the requested object from the message (second part of the HTTP header)
            filename = message.split()[1]

            # 3. Read the corresponding file from disk
            with open(filename[1:], 'r') as f:  # Skip the leading '/'
                content = f.read()

            # 4. Create the HTTP response
            response = 'HTTP/1.1 200 OK\r\n\r\n'
            response += content

            # 5. Send the content of the file to the socket
            connectionSocket.send(response.encode())

        except IOError:
            # Handle file not found error
            error_response = "HTTP/1.1 404 Not Found\r\n\r\n"
            error_response += "<html><head></head><body><h1>404 Not Found</h1></body></html>\r\n"
            connectionSocket.send(error_response.encode())

        except Exception as e:
            print(f"Error handling request: {e}")

        finally:
            # Close the connection socket
            connectionSocket.close()

# A proxy implementation 
class Proxy(NetworkApplication):

    def __init__(self, args):
        print('Web Proxy starting on port: %i...' % (args.port))
        
        
        # Cache dictionary: maps URLs to file paths
        self.cache = {}
        self.cache_directory = "./cache"
        os.makedirs(self.cache_directory, exist_ok = True)
        
        # Create a TCP socket for the proxy server
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Bind the socket to the given port
        serverSocket.bind(("", args.port))
        
        # Start listening for incoming connections
        serverSocket.listen(100)
        print("Proxy listening on port", args.port)

        while True:
            connectionSocket, addr = serverSocket.accept()
            print(f"Connection established with {addr}")
            
            # Create a new thread to handle the client request
            threading.Thread(target=self.handleRequest, args=(connectionSocket,)).start()
            
        serverSocket.close()

    def handleRequest(self, connectionSocket):
        try:
            
            message = connectionSocket.recv(MAX_DATA_RECV).decode()
            print(f"Request received: {message.splitlines()[0]}")

            # Parse the HTTP request to extract the destination host and port
            firstLine = message.splitlines()[0]
            url = firstLine.split()[1]

            http_pos = url.find("://") 
            if http_pos != -1:
                url = url[(http_pos + 3):]

            # Extract host and port
            host, path = url.split("/", 1)  
            if ":" in host:
                host, dest_port = host.split(":")
                dest_port = int(dest_port)
            else:
                dest_port = 80 # Default port if no port is provided
            
            
             # Check if the URL is cached
            cache_key = f"{host}{path}"
            if cache_key in self.cache:
                
                print(f"Cache found for URL: {cache_key}")
                self.serveCachedResponse(connectionSocket, cache_key)
                
            elif cache_key not in self.cache:
                
                print(f"Cache not found for URL: {cache_key}. Fetching from server.")
                self.cacheResponse(connectionSocket, host, dest_port, path, cache_key, message)

        except Exception as error:
            print(f"Error handling proxy request: {error}")
            
        finally:
            # Close socket
            connectionSocket.close()

    def serveCachedResponse(self, connectionSocket, cache_key):
        # Serve cached response by reading the file from ./cache
        cache_path = self.cache[cache_key]
        
        try:
            
            with open(cache_path, 'rb') as cached_file:
                
                while (chunk := cached_file.read(MAX_DATA_RECV)):
                    connectionSocket.send(chunk)
                    
            print(f"Served cached response for {cache_key}")
            
        except IOError:
            print(f"Failed to serve cached response for {cache_key}")

    def cacheResponse(self, connectionSocket, host, port, path, cache_key, message):
        # Connect to the destination server
        destinationSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        destinationSocket.connect((host, port))
        destinationSocket.send(message.encode())

        # Cache the response
        cache_path = os.path.join(self.cache_directory, cache_key.replace("/", "_"))
        
        with open(cache_path, 'wb') as cache_file:
            
            while True:
                
                serverResponse = destinationSocket.recv(MAX_DATA_RECV)
                
                if len(serverResponse) == 0:
                    break
                
                # Save response to cache and send it to the terminal
                cache_file.write(serverResponse)
                connectionSocket.send(serverResponse)
                
        # Update cache dictionary
        self.cache[cache_key] = cache_path
        print(f"Cached response for {cache_key} at {cache_path}")

        destinationSocket.close()
        
if __name__ == "__main__":
        
    args = setupArgumentParser()
    args.func(args)