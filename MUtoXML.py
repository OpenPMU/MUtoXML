"""OpenPMU MU to XML"""

from __future__ import print_function
import csv
import matplotlib.pyplot as plt
import os
import time
from datetime import datetime, timedelta
import numpy as np
import socket
from lxml import etree
import base64
from PyQt5.QtCore import QThread
import scipy.signal as signal

SCRIPT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))

# convert from dict to xml value
# if no conversion needed, delete it from the expression
dictTypeConvert = lambda key: {'Frame': str,
                               'Fs': str,
                               'n': str,
                               'Channels': str,
                               'Payload': base64.standard_b64encode,
                               'bits': str,
                               }.get(key, lambda x: x)

# Code for reading CSV file and Sample CSV file is from https://github.com/mgadelha/Sampled_Values

# Read and parse CSV data
def readcsv(filename):
    """Read and parse Wireshark SV-CSV data"""
    with open(filename) as csvfile:
        spamreader = csv.reader(csvfile, delimiter=';')
        data = []
        for row in spamreader:
            data.append(row[0].replace('"', '').split(','))

    # Unpack data into a dictionary
    parsedata = dict((k, []) for k in data[0])
    values = ['IA', 'IB', 'IC', 'IN', 'VA', 'VB', 'VC', 'VN']
    parsedata['value'] = dict((k, []) for k in values)

    # Parse Wireshark CSV collumn data
    for item in data[1:]:

        parsedata['No.'].append(int(item[0]))
        parsedata['Time'].append(float(item[1]))
        parsedata['Source'].append(item[2])
        parsedata['Destination'].append(item[3])
        parsedata['Protocol'].append(item[4])
        parsedata['Length'].append(item[5])
        parsedata['Time delta from previous displayed frame'].append(
            float(item[6]))
        parsedata['smpCnt'].append(int(item[7]))
        if item[8] == 'global':
            smpsynch = 2
        elif item[8] == 'local':
            smpsynch = 1
        else:
            smpsynch = 0
        parsedata['smpSynch'].append(int(smpsynch))
        for key, val in zip(values, item[9:17]):
            parsedata['value'][key].append(float(val))
        
    return parsedata

def plot(dictdata):
    """Plot SV data"""
    fig, ax = plt.subplots(3,1, constrained_layout=True)

    plt.figure(1)
    plt.suptitle('Merging Unit', fontsize=18, fontweight='bold')
    plt.legend(loc='upper right', fontsize=14)

    ax[0].set_ylabel('IA')
    ax[0].set_xlabel('Time')
    ax[0].set_title('IA (A Primary)', fontsize=12)
    ax[0].plot(dictdata['Time'], np.multiply(dictdata['value']['IA'],0.001), '-*', color='blue')
           
    ax[1].set_ylabel('SmpCnt')
    ax[1].set_xlabel('Time')
    ax[1].set_title('smpCnt',  fontsize=12)
    ax[1].plot(dictdata['Time'], dictdata['smpCnt'], '-', color='red')

    ax[2].set_ylabel('smpSynch')
    ax[2].set_xlabel('Time')
    ax[2].set_title('smpSynch',  fontsize=12)
    ax[2].plot(dictdata['Time'], dictdata['smpSynch'], '-', color='red')           
             
    plt.show()


class MUtoOpenPMU(QThread):
    def __init__(self, SVdataIn, channels=8, ip="127.0.0.1", port=48001):
        QThread.__init__(self, )

        self.SVdataIn = SVdataIn
        self.channels = channels

        self.interval = 0.01  # seconds
        self.Fs = 12800
        self.n = int(self.Fs * self.interval)
        self.ADCRange = 2 ** 15 - 1
        self.bits = 16

        self.ip = ip
        self.port = port

        self.stopThread = False
        self.xmlTemplate = etree.parse(os.path.join(SCRIPT_DIRECTORY, "OpenPMU_SV.xml"))

    def run(self):
        self.stopThread = False
        
        timeStart = datetime.now()

        socketOut = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        socketFwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)    
        # basic information
        resultDict = dict()
        resultDict["Fs"] = self.Fs
        resultDict["n"] = self.n
        resultDict["Channels"] = self.channels
        resultDict["bits"] = self.bits

        # frame count
        frame = 0
        # time information for cos function
        intervalDelta = timedelta(seconds=self.interval)
        
        SVgen = self.SVdataGen(self.SVdataIn)
        
        while not self.stopThread:
            now = datetime.now()
            resultDict["Time"] = now.time().strftime("%H:%M:%S") + ".%03d" % (frame * self.interval * 1000)
            resultDict["Date"] = now.date().strftime("%Y-%m-%d")
            resultDict["Frame"] = frame

            try:
                payload = next(SVgen)
            except:
                self.stop()
                break
            
            for i in range(self.channels):
                Channel_i = "Channel_%d" % i
                resultDict[Channel_i] = dict()
                resultDict[Channel_i]["Payload"] = np.ascontiguousarray(payload[i, :])

            xml = self.toXML(resultDict)
            # print(xml)
            socketOut.sendto(xml, (self.ip, self.port))
            socketFwd.sendto(xml, ("127.0.0.1", 48005))    
            
            frame += 1
            if (frame == int(1 / self.interval)):
                frame = 0

            # delay some time, this is not accurate
            s = (intervalDelta - (datetime.now() - now)).total_seconds()
            print((datetime.now() - timeStart).total_seconds())
            time.sleep(s if s > 0 else 0)

    def stop(self):
        self.stopThread = True

    # convert from python dictionary to a XML string
    def toXML(self, resultDict):
        level0 = self.xmlTemplate.getroot()

        try:
            for level1 in list(level0):
                tag1 = level1.tag
                if tag1 in resultDict.keys():
                    if tag1.startswith("Channel_"):
                        for level2 in list(level1):
                            tag2 = level2.tag
                            if tag2 in resultDict[tag1].keys():
                                # print(resultDict[tag1][tag2])
                                level2.text = dictTypeConvert(tag2)(resultDict[tag1][tag2])

                    else:
                        level1.text = dictTypeConvert(tag1)(resultDict[tag1])
                else:
                    level0.remove(level1)
        except KeyError as e:
            print("XML tag error: ", e)
        xml = etree.tostring(level0, encoding="utf-8")
        return xml
    
    def SVdataGen(self, SVdataIn):

        channels = self.channels

        fS_in  = 80
        fS_out = 256
        
        SVdata = np.empty(0)
        
        for key in MUdata['value']:
            
            print(key)   
        
            chData = np.array(MUdata['value'][key])
            
            noSamples = len(chData)
            noWindows = int(noSamples / fS_in)
            chData = chData[0: fS_in * noWindows]
            
            chData = signal.resample(chData, fS_out * noWindows)
            
            # Data is at 80 s/cyc, needs to be 256 s/cyc
            
            chMax = max(abs(chData))
            
            chData = (chData / ( chMax / 2**15)).astype(np.int16)
            
            print(chMax)
            
            try:
                SVdata = np.vstack((SVdata, chData))
            except:
                SVdata = chData
                
        
        blocksize = 128
        
        i = 0
        while i < int(len(SVdata[0])/blocksize):
            
            SVpart = SVdata[0:self.channels, i*blocksize: (i+1)*blocksize]
            print(i, SVpart.shape)
            i += 1
            yield SVpart.byteswap()


if __name__ == '__main__':
    print('Normal_traffic_NIC_COFFEE.csv')
    DATA = readcsv('SV_normal.csv')
    
    MUdata = DATA
    
    OpenPMUsim = MUtoOpenPMU(MUdata)
    OpenPMUsim.run()
    #plot(DATA)