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
        try:
            destinationAddress = socket.gethostbyname(args.hostname)
        except socket.gaierror:
            print("Host address could not be found, ensure address is valid and exists")
            return

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
        
        if(protocol.upper() == 'ICMP'):
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
        
        elif(protocol.upper() == 'UDP'):

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

        #Always recieve the packets through an ICMP Socket

        try:
            data, address = icmpSocket.recvfrom(1024)
            sourceIP = address[0]

            endTime = time.time()

            ICMPHeader = data[20:28]
            ICMPType, ICMPCode, checksum, recievedID, ICMPSeq = struct.unpack("!BBHHH", ICMPHeader)

            #Type 11 - Time exceeded 
            #Type 0 - Destination Reached
            #Type 3 - Destination Unreachable (needed for UDP)

            if(ICMPType == 11 or ICMPType == 0 or ICMPType == 3):
                IPHeader = data[:20]
                IPTTL = struct.unpack("!B", IPHeader[8:9])[0]
            else:
                print("Recieved ID and Packet ID did not match")
                return None

            packetSize = len(data)
            
            return endTime, IPTTL, packetSize, ICMPSeq, ICMPType, sourceIP

        except socket.timeout:
            #print("Socket Timeout")
            return 1
        
        pass



    def doOneTrace(self, destinationAddress, packetID, timeout, ttl, protocol):

        #Open correct socket based on user's input of protocol
        if protocol == 'ICMP' or protocol == 'icmp':
            ourSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        elif protocol == 'UDP' or protocol == 'udp':
            ourSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        else:
            print("Invalid protocol. Supported protocols are ICMP and UDP.")
            return True

        receiveSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

        seq_num = 1
        rttArray = []

        #Send out 3 packets
        while seq_num <= 3:
            sentTime = self.sendOneTrace(ourSocket, destinationAddress, packetID, seq_num, ttl, protocol)
            results = self.receiveOneTrace(receiveSocket, packetID, timeout)
            seq_num = seq_num + 1
            socketTimeout = False

            if results is not None and results != 1:
                endTime, IPTTL, packetSize, ICMPSeq, ICMPType, sourceIP = results
                rtt = (endTime - sentTime) * 1000
                rttArray.append(rtt) #Collecting time data
            elif results == 1:
                socketTimeout = True
    
        if socketTimeout == True:   #If all 3 packets resulted in a timeout, print * to indicate such
            print(ttl, "* * *")
            return
        
        #Try and retrive the host name from the source IP (if there is one)
        try:
            hostInfo = socket.gethostbyaddr(sourceIP)
            hostName = hostInfo[0]
        except socket.herror:
            hostName = str(sourceIP) 

        #If we recieve type 0 or 3 (destination reached/unreachable) break the main loop
        if(ICMPType == 0 or ICMPType == 3):
                self.printOneTraceRouteIteration(ttl, sourceIP, rttArray, hostName)
                ourSocket.close()
                receiveSocket.close()
                return True

        #Otherwise, print out the details of this hop and move on
        self.printOneTraceRouteIteration(ttl, sourceIP, rttArray, hostName)
        ourSocket.close()
        receiveSocket.close()

        pass



    def __init__(self, args):
        print('Traceroute to: %s...' % (args.hostname))

        #Get the user's desired destination
        try:
            destinationAddress = socket.gethostbyname(args.hostname)
        except socket.gaierror:
            print("Host address could not be found, ensure address is valid and exists")
            return

        #Initalise values, random packet id and args for timeout and protocol
        packetID = random.randint(1, 10000)
        timeout = args.timeout
        protocol = args.protocol
        maxHops = 30
        ttl = 1

        #The ttl starts at 1 and goes on for the max amount of hops (traceroute default is 30)
        #Each time round, the ttl is increased meaning we got to the next router
        while ttl < (maxHops + 1):
            end = self.doOneTrace(destinationAddress, packetID, timeout, ttl, protocol)
            ttl = ttl + 1

            if(end == True):
                break
        



  #*************************************************************************************************************************************************************************
 




class WebServer(NetworkApplication):
    def handleRequest(self, tcpSocket):
        try:
            # 1. Receive request message from the client on connection socket
            requestMessage = tcpSocket.recv(1024)
            requestMessageString = requestMessage.decode('utf-8')
            requestDecoded = requestMessageString.split('\r\n')

            #print("Request Message: ", requestDecoded[0])

            # 2. Extract the path of the requested object from the message
            if len(requestDecoded[0]) > 0:
                method, path, _ = requestDecoded[0].split(' ')

                # 3. Read the corresponding file from disk
                # 4. Store in temporary buffer
                if method == 'GET':
                    if path.startswith('/'):
                        path = path[1:]
                    if os.path.isfile(path):
                        with open(path, 'rb') as file:
                            content = file.read()

                        response = 'HTTP/1.1 200 OK\r\n'
                        response += 'Content-Type: text/html\r\n'
                        response += '\r\n'
                        response = response.encode() + content

                    # 5. Send the correct HTTP response error
                    else:
                        # ERROR 404
                        response = 'HTTP/1.1 404 Not Found\r\n'
                        response += 'Content-Type: text/plain\r\n'
                        response += '\r\n'
                        response += 'File not found.'
                        response = response.encode()

                else:
                    # ERROR 501
                    response = 'HTTP/1.1 501 Not Implemented\r\n'
                    response += 'Content-Type: text/plain\r\n'
                    response += '\r\n'
                    response += 'Method not supported.'
                    response = response.encode()

        except Exception as e:
            # ERROR 500 (for try catch)
            response = 'HTTP/1.1 500 Internal Server Error\r\n'
            response += 'Content-Type: text/plain\r\n'
            response += '\r\n'
            response += str(e)
            response = response.encode()

        # 6. Send the content of the file to the socket
        tcpSocket.sendall(response)

        # 7. Close the connection socket
        tcpSocket.close()

    def __init__(self, args):
        print('Web Server starting on port: %i...' % (args.port))

        try:
            # 1. Create server socket
            port = args.port
            serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # 2. Bind the server socket to server address and server port
            serverSocket.bind(('127.0.0.1', port))

            # 3. Continuously listen for connections to server socket
            serverSocket.listen()
            print("Listening for connections...")
            while True:
                acceptedSocket, _ = serverSocket.accept()
                self.handleRequest(acceptedSocket)

        finally:
            # 4. Close server socket
            serverSocket.close()



class Proxy(NetworkApplication):

    def handleRequest(self, tcpSocket):
        requestMessage = tcpSocket.recv(1024).decode('utf-8') #Get the message
        requestParts = requestMessage.split('\r\n')

        #To check for correct message:
        # print("MESSAGE: ", requestMessage)

        if len(requestParts[0]) > 0:
            method, url, _ = requestParts[0].split(' ') #Get the method and url/path

            #Remove "http://" 
            url_parts = url.split('//')
            if len(url_parts) > 1:
                url = url_parts[1]

            if method == 'GET':
                cachedResponse = self.fetchCache(url) #See if it exists in the cache

                if cachedResponse:
                    tcpSocket.sendall(cachedResponse.encode()) #If it does, send it out
                    tcpSocket.close()
                else:
                    serverResponse = self.forwardRequest(url) #If it doesn't, forward request to web server 
                    self.updateCache(url, serverResponse)     #Then update our cache with the response
                    tcpSocket.sendall(serverResponse.encode())#Finally send out the response
                    tcpSocket.close()


    #Helper function to get a response of a related url from the cache if it exists
    def fetchCache(self, url):
        if url in self.cache:
            return self.cache[url]['response']
        else:
            return None
        

    #Helper function to update the cache
    def updateCache(self, url, response):
        self.cache[url] = {'response': response}



    def forwardRequest(self, url):
        host, path = url.split('/', 1) if '/' in url else (url, '') #Split host and the path
        try:
            serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            serverSocket.connect((host, 80))  #Connect to the web server
            request = f"GET /{path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n" #Create a request
            serverSocket.sendall(request.encode()) #Send the request

            response = b''
            while True: #while loop incase of dodgy transmission
                data = serverSocket.recv(1024)
                if not data:
                    break
                response += data

            serverSocket.close()
            return response.decode()
        except socket.gaierror: #Send back an error 404 if thats what we recieved back from the web server
            return "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nRequested webpage not found."


    def __init__(self, args):
        print('Web Proxy starting on port: %i...' % (args.port))

        #Our cache is a python dictionary
        self.cache = {}

        try:
            port = args.port
            serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            serverSocket.bind(('127.0.0.1', port))

            serverSocket.listen()
            print("Listening for connections...")
            while True:
                acceptedSocket, _ = serverSocket.accept()
                self.handleRequest(acceptedSocket)

        finally:
            serverSocket.close()




# Do not delete or modify the code below
if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)
