# coding=utf-8
import os
import dpkt
import socket
import uuid
import time
import psutil
import subprocess
from scapy.sendrecv import sniff
from scapy.utils import wrpcap
from pynput import keyboard


# get dpkt module
def get_dpkt():
    dpkt_ = sniff(count=100)
    _uuid = uuid.uuid1()
    filename = 'test.pcap'
    wrpcap(filename, dpkt_)

    return filename


# analyse pcap packet
def print_pcap(pcap):
    try:
        for timestamp, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)

            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            # packet with detector string
            if ("abcde" in ip.data.data):
                print("Detected the dangerous email, Sender IP: %s, Receiver IP: %s" % (dst_ip, src_ip))
                print("！！！！！！！！！！！！！！！！！！！！！！！！")
                print(ip.data.data)
                print("！！！！！！！！！！！！！！！！！！！！！！！！")
                # time to kill
                doKill(src_ip)
                print("----------------------------------------")
            # other email actions
            elif ("smtp" in ip.data.data) or ("pop3" in ip.data.data) or ("imap" in ip.data.data) or (
                    "RecverEmail" in ip.data.data):
                print("Detected the suspicious email, Sender IP: %s, Receiver IP: %s" % (dst_ip, src_ip))
                print(ip.data.data)
                print("----------------------------------------")
    except Exception as error:
        pass


# Scans for processes that communicate with addresses
def findPID(ip):
    while (True):
        netstats = psutil.net_connections()
        for netstat in netstats:
            if (len(netstat.raddr) > 0):
                if ((ip == netstat.raddr.__getitem__(0)) and (netstat.pid > 0)):
                    print("Process address is: %s, pid is: %s" % (netstat.raddr, netstat.pid))
                    return netstat.pid


# Kill process through process_name
def killProcess(pid):
    p = psutil.Process(pid)
    # get process name according to pid
    print(p.name())
    # kill process
    print("kill specific process: name(%s)" % (p.name()))
    subprocess.Popen("cmd.exe /k taskkill /f /im %s" % p.name(), shell=True)
    # delete exe file
    os.remove(p.exe())


def doKill(ip):
    killProcess(findPID(ip))


if __name__ == '__main__':
    print("Detector is running...")
    PUSH_SPEED = 0.1

    time.sleep(1)
    keyboard_c = keyboard.Controller()
    keyboard_c.press('a')
    time.sleep(PUSH_SPEED)
    keyboard_c.release('a')
    time.sleep(PUSH_SPEED)
    keyboard_c.press('b')
    time.sleep(PUSH_SPEED)
    keyboard_c.release('b')
    time.sleep(PUSH_SPEED)
    keyboard_c.press('c')
    time.sleep(PUSH_SPEED)
    keyboard_c.release('c')
    time.sleep(PUSH_SPEED)
    keyboard_c.press('d')
    time.sleep(PUSH_SPEED)
    keyboard_c.release('d')
    time.sleep(PUSH_SPEED)
    keyboard_c.press('e')
    time.sleep(PUSH_SPEED)
    keyboard_c.release('e')

    print("Detecting the suspicious packet...")
    while True:
        filename = get_dpkt()
        with open(filename, "rb") as f:
            pcap = dpkt.pcap.Reader(f)
            print_pcap(pcap)
        os.remove(filename)
