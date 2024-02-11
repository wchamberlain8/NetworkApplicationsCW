#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import socket
import os
import sys
import struct
import time
import random
import traceback # useful for exception handling
import threading
# NOTE: Do not import any other modules - the ones above should be sufficient

def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications developed for SCC.203.')
        parser.set_defaults(func=ICMPPing, hostname='lancaster.ac.uk')
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
        parser_t.set_defaults(timeout=2, protocol='icmp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)
        
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

    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, seq: int, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%.3f ms" % (packetLength, destinationHostname, destinationAddress, seq, ttl, time))
        else:
            print("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms" % (packetLength, destinationAddress, seq, ttl, time))

    def printAdditionalDetails(self, packetLoss=0.0, minimumDelay=0.0, averageDelay=0.0, maximumDelay=0.0):
        print("%.2f%% packet loss" % (packetLoss))
        if minimumDelay > 0 and averageDelay > 0 and maximumDelay > 0:
            print("rtt min/avg/max = %.2f/%.2f/%.2f ms" % (minimumDelay, averageDelay, maximumDelay))

    def printOneTraceRouteIteration(self, ttl: int, destinationAddress: str, measurements: list, destinationHostname=''):
        latencies = ''
        noResponse = True
        for rtt in measurements:
            if rtt is not None:
                latencies += str(round(rtt, 3))
                latencies += ' ms  '
                noResponse = False
            else:
                latencies += '* ' 

        if noResponse is False:
            print("%d %s (%s) %s" % (ttl, destinationHostname, destinationAddress, latencies))
        else:
            print("%d %s" % (ttl, latencies))

class ICMPPing(NetworkApplication):

    #**************************************************************************************************************************************

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout):
        # 1. Wait for the socket to receive a reply
        # 2. If reply received, record time of receipt, otherwise, handle timeout

        icmpSocket.settimeout(timeout)

        try:

            data, address = icmpSocket.recvfrom(1024) #get the data

            endTime = time.time()
        
            # 3. Unpack the imcp and ip headers for useful information, including Identifier, TTL, sequence number
            # 4. Check that the Identifier (ID) matches between the request and reply

            ICMPHeader = data[20:28]    #ICMP header starts at 20 bytes
            ICMPType, ICMPCode, checksum, packetID, ICMPSeq = struct.unpack("!BBHHH", ICMPHeader)

            if(packetID == ID): #check IDs match
                IPHeader = data[:20]
                ttl = struct.unpack("!B", IPHeader[8:9])[0]
            else:
                print("ICMP ID and Packet ID did not match")

            packetSize = len(data)

            
            # 6. Return time of receipt, TTL, packetSize, sequence number
                
            return endTime, ttl, packetSize, ICMPSeq
    
        except socket.timeout:
                print("Socket timeout")
                return None
        
        pass



    def sendOnePing(self, icmpSocket, destinationAddress, ID, seqNum):
        # 1. Build ICMP header

        ICMPHeader = struct.pack("!BBHHH", 8, 0, 0, ID, seqNum)

        # 2. Checksum ICMP packet using given function

        checksum = self.checksum(ICMPHeader)


        # 3. Insert checksum into packet

        ICMPHeader = struct.pack("!BBHHH", 8, 0, socket.htons(checksum), ID, seqNum)

        # 4. Send packet using socket
        destinationAddress = (destinationAddress, 0)
        icmpSocket.sendto(ICMPHeader, destinationAddress)

        # 5. Return time of sending

        return time.time()
        
        pass



    def doOnePing(self, destinationAddress, packetID, seq_num, timeout):
        lostPackets = 0
        
        # 1. Create ICMP socket

        ICMPSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

        try:
            # 2. Call sendOnePing function
            sentTime = self.sendOnePing(ICMPSocket, destinationAddress, packetID, seq_num)

            # 3. Call receiveOnePing function
            # 5. Print out the delay (and other relevant details) using the printOneResult method

            results = self.receiveOnePing(ICMPSocket, destinationAddress, packetID, timeout)

            if results is not None:
                endTime, ttl, packetSize, sequenceNum = results
                rtt = (endTime - sentTime) * 1000
                destinationHostname = socket.gethostbyaddr(destinationAddress)[0]
                self.printOneResult(destinationAddress, packetSize, rtt, sequenceNum, ttl, destinationHostname)
            else:
                lostPackets += 1

        finally:
            # 4. Close ICMP socket

            ICMPSocket.close()
            return rtt, lostPackets

        
        pass


    def __init__(self, args):
        print('Ping to: %s...' % (args.hostname))
        # 1. Look up hostname, resolving it to an IP address
        destinationAddress = socket.gethostbyname(args.hostname)

        # 2. Repeat below args.count times
        # 3. Call doOnePing function, approximately every second, below is just an example

        seqNum = 0
        packetID = random.randint(1, 10000)
        rttArray = []
        packetLoss = 0

        count = args.count

        while count > 0:
            rtt, lostPackets = self.doOnePing(destinationAddress, packetID, seqNum, args.timeout)
            time.sleep(0.1)
            count -= 1
            seqNum += 1
            packetLoss = packetLoss + lostPackets
            rttArray.append(rtt)
        
        #self.printAdditionalDetails() - need to get min max times, avg time, get initial packet size to send and end to get loss rate
        minRTT = min(rttArray)
        avgRTT = sum(rttArray) / len(rttArray)
        maxRTT = max(rttArray)
        packetLossPercentage = (packetLoss / args.count) * 100

        self.printAdditionalDetails(packetLossPercentage, minRTT, avgRTT, maxRTT)





#*************************************************************************************************************************************************************************





class Traceroute(NetworkApplication):

    def sendOneTrace(self, ourSocket, destinationAddress, ID, seqNum, ttl, protocol):
        
        if(protocol == 'ICMP'):
            #Build ICMP header 
            ICMPHeader = struct.pack("!BBHHH", 8, 0, 0, ID, seqNum)
            
            #Set TTL value in header
            ourSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            
            checksum = self.checksum(ICMPHeader)

            #Rebuild header
            ICMPHeader = struct.pack("!BBHHH", 8, 0, socket.htons(checksum), ID, seqNum)

            #Send packet using socket
            destinationAddress = (destinationAddress, 0)
            ourSocket.sendto(ICMPHeader, destinationAddress)

            return time.time()
        
        elif(protocol == 'UDP'):

            #BUILD HEADER, SET TTL IN HEADER, REBUILD HEADER WITH CHECKSUM, SEND PACKET USING SOCKET

            sourcePort = random.randint(33433, 60000)
            destinationPort = 33433 + seqNum

            UDPHeader = struct.pack("!HHHH", sourcePort, destinationPort, 8, 0)

            ourSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

            checksum = self.checksum(UDPHeader)

            UDPHeader = struct.pack("!HHHH", sourcePort, destinationPort, 8, socket.htons(checksum))

            destinationAddress = (destinationAddress, destinationPort)
            ourSocket.sendto(UDPHeader, destinationAddress)

            return time.time()
    
    
    def receiveOneTrace(self, icmpSocket, packetID, timeout):
        icmpSocket.settimeout(timeout)

        try:
            data, address = icmpSocket.recvfrom(1024)
            sourceIP = address[0]

            endTime = time.time()

            ICMPHeader = data[20:28]
            ICMPType, ICMPCode, checksum, recievedID, ICMPSeq = struct.unpack("!BBHHH", ICMPHeader)

            if(ICMPType == 11 or ICMPType == 0 or ICMPType == 3):
                IPHeader = data[:20]
                IPTTL = struct.unpack("!B", IPHeader[8:9])[0]
            else:
                print("Recieved ID and Packet ID did not match")
                return None

            packetSize = len(data)
            
            return endTime, IPTTL, packetSize, ICMPSeq, ICMPType, sourceIP

        except socket.timeout:
            print("Socket Timeout")
            return 1
        
        pass



    def doOneTrace(self, destinationAddress, packetID, timeout, ttl, protocol):

        if protocol == 'ICMP' or protocol == 'icmp':
            ourSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        elif protocol == 'UDP' or protocol == 'udp':
            ourSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        else:
            print("Invalid protocol. Supported protocols are ICMP and UDP.")
            return

        receiveSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

        seq_num = 1
        rttArray = []

        while seq_num <= 3:
            sentTime = self.sendOneTrace(ourSocket, destinationAddress, packetID, seq_num, ttl, protocol)
            results = self.receiveOneTrace(receiveSocket, packetID, timeout)
            seq_num = seq_num + 1
            socketTimeout = False

            if results is not None and results != 1:
                endTime, IPTTL, packetSize, ICMPSeq, ICMPType, sourceIP = results
                rtt = (endTime - sentTime) * 1000
                rttArray.append(rtt)
            elif results == 1:
                socketTimeout = True
                print("* ")
    
        if socketTimeout == True:
            return
        
        try:
            hostInfo = socket.gethostbyaddr(sourceIP)
            hostName = hostInfo[0]
        except socket.herror:
            hostName = str(sourceIP) 

        if(ICMPType == 0 or ICMPType == 3):
                self.printOneTraceRouteIteration(ttl, sourceIP, rttArray, hostName)
                ourSocket.close()
                receiveSocket.close()
                return True

        self.printOneTraceRouteIteration(ttl, sourceIP, rttArray, hostName)
        ourSocket.close()
        receiveSocket.close()

        pass



    def __init__(self, args):
        print('Traceroute to: %s...' % (args.hostname))

        destinationAddress = socket.gethostbyname(args.hostname)
        packetID = random.randint(1, 10000)
        #packetID = 0
        timeout = args.timeout
        protocol = args.protocol
        maxHops = 30
        ttl = 1

        while ttl < (maxHops + 1):
            end = self.doOneTrace(destinationAddress, packetID, timeout, ttl, protocol)
            ttl = ttl + 1

            if(end == True):
                break
        

   


class WebServer(NetworkApplication):

    def handleRequest(self, tcpSocket):
        # 1. Receive request message from the client on connection socket
        requestMessage, requestAddress = tcpSocket.recvfrom(1024)
        requestMessageString = str(requestMessage, 'utf-8')
        requestDecoded = requestMessageString.split('\r\n')

        print("Request Message: ", requestDecoded[0])

        # 2. Extract the path of the requested object from the message (second part of the HTTP header)

        if(len(requestDecoded[0]) > 0):
            method, path, type = requestDecoded[0].split(' ')
            print("METHOD: ", method)
            print("PATH: ", path)
            print("TYPE: ", type)

        # 3. Read the corresponding file from disk
        # 4. Store in temporary buffer
            
        if(method == 'GET'):
            if path.startswith('/'):
                path = path[1:]
            if os.path.isfile(path):
                with open(path, 'rb') as file:
                    content = file.read()

                    print("ATTEMPTING TO READ!")

                    response = 'HTTP/1.1 200 OK\r\n'
                
                    response += content.decode()

            # 5. Send the correct HTTP response error
            else:
                # Error 404
                response = 'HTTP/1.1 404 Not Found\r\n'
                response += 'File not found.'
        else:
            # Error 501
            response = 'HTTP/1.1 501 Not Implemented\r\n'
            response += 'Method not supported.'
        
        
        # 6. Send the content of the file to the socket
            
        tcpSocket.sendall(response.encode())

        # 7. Close the connection socket
        tcpSocket.close()
        pass




    def __init__(self, args):
        print('Web Server starting on port: %i...' % (args.port))

        try:
            # 1. Create server socket - COULD USE SERVERSOCKET LIBRARY OR CREATE SOCKET AS socket.create_server ????
            port = args.port
            serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # 2. Bind the server socket to server address and server port
            serverSocket.bind(('127.0.0.1', port))

            # 3. Continuously listen for connections to server socket
            # 4. When a connection is accepted, call handleRequest function, passing new connection socket (see https://docs.python.org/3/library/socket.html#socket.socket.accept)
            serverSocket.listen()
            print("Listening for connections...")
            while True:
                acceptedSocket, acceptedAddress = serverSocket.accept()
                self.handleRequest(acceptedSocket)

        finally:
            # 5. Close server socket
                
            serverSocket.close()



class Proxy(NetworkApplication):

    def __init__(self, args):
        print('Web Proxy starting on port: %i...' % (args.port))

# Do not delete or modify the code below
if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)
