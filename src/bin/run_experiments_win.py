#!/usr/bin/env python3
# ZIP run experiments script
import glob
import subprocess
import re
import sys
import signal
import time
import datetime
import os
import math

def signal_handler(signal, frame):
    print("Crtl + C catched")
    p.kill()
    out.close()
    sys.exit()
    
if len(sys.argv) < 4:
    print ("not enough arguments")
    print ("""  
    1: zip / 7z - ZIP / 7z switch
    2: c / g - CPU / GPU switch
    3: [number] - number of processes to run or first GPU to use
    4: [number] - number of last GPU to use
    5: hdr - for 7z only / [256/192/128] for zip as key bit length [default:256]
                """)
    sys.exit(1)

path = "testfiles\\experiments\\"
if sys.argv[1] == "zip":
    gws = [225024, 450048, 450048, 450048]
    if not (6 in sys.argv):
        blen = "256"
    else:
        blen = sys.argv[5]
    path += "securezip\\"
    files_in_dir = "*"+blen+"*z.zip"

elif sys.argv[1] == "7z":
    path += "7z\\"
    if 6 in sys.argv:
        if sys.argv[5] == "hdr":
            files_in_dir= "*z_hdr.7z"
    else:
        files_in_dir= "*z.7z"
    gws = [64, 64, 64, 64]

if path == "":
    print("I wasnt able to determine the path!")
    sys.exit(10)

if sys.argv[2] == 'g':
    devices = "-d "
    for i in range(int(sys.argv[3]), int(sys.argv[4])+1):
        devices += "0:" + str(i) + ":" + str(gws[i])
        if i < int(sys.argv[4]):
            devices += ","
    instances = int(sys.argv[4])+1 - int(sys.argv[3])
elif sys.argv[2] == 'c':
    devices = "-ct" + sys.argv[3] 
    instances = int(sys.argv[3])

filename = ""
for i in range(1, len(sys.argv)):
    filename += sys.argv[i]
    if i < len(sys.argv):
        filename += "_"
filename += ".out"

#ca = subprocess.Popen("./clearall.sh", shell=True)
#ca.wait()

files = glob.glob(path+files_in_dir)
files.sort()

out = open(filename, "a")
signal.signal(signal.SIGINT, signal_handler)
completed = 0


for f in files:
    print ("\n############################################################\n")
    print ("Cracking file: "+f)
    now = datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d %H:%M:%S')
    print ("Maximal time till end: "+str(math.ceil((len(files) - completed))*10)+ " minutes from: "+now)
    print ("""
    If you need something use Crtl+C and when you are done turn me on again with args I
    ran with and I will continue my work! Thank you for your cooperation.
    """)
    p = subprocess.Popen("wrathion.exe -v " + devices  + " -f " + f, 
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    try:
        stdout, stderr = p.communicate(timeout=60*10) # 10 minutes
        timedout = False
    except subprocess.TimeoutExpired:
        p.kill()
        timedout = True
    str_stdout = str(stdout)
    r_speeds = re.compile('Thread [0-9]{1,2}: ([0-9]*) p/s[,]{0,1}')
    l_speeds = re.findall(r_speeds,str_stdout)

    if (len(l_speeds) > 0):
        avg_thread_speed = math.ceil(sum(int(x) for x in l_speeds) / len(l_speeds))
        avg_total_speed = avg_thread_speed * instances
    else:
        avg_thread_speed = 0
        avg_total_speed = 0

    #out.write(str_stdout)
    r_time = re.compile(
      r'Total time spent by cracking:\\r\\n(.*)\s\\r\\n', re.UNICODE)
    
    if r_time:
        l_time = re.findall(r_time,str_stdout)
    else:
        print("Something went wrong with parsing output.")
    
    time = '%s' % ', '.join(map(str, l_time))
    
    if not timedout: 
        msg = (f + "; avg_thread_speed: " + str(avg_thread_speed) +
            "h/s; avg_total_speed: " + str(avg_total_speed) + 
            "h/s; time: " + time)
    else:
        msg = f + "; Timedout!"
        msg = (f + "; avg_thread_speed: " + str(avg_thread_speed) +
            "h/s; avg_total_speed: " + str(avg_total_speed) + 
            "h/s; time: Timedout!")
    out.write(msg+"\r")
    out.write("stderr:\n" + str(stderr))
    completed += 1
    r_exp_filename = re.escape(path)+u"(.*)$"
    s_exp_filename = re.search(r_exp_filename,f)
    
    if s_exp_filename:
        exp_filename = s_exp_filename.group(1)    
    else:
        exp_filename = ""
        print("Something went wrong with parsing output.")
    
    
    print (exp_filename)
    os.rename(f, path + "finished\\" + exp_filename)
    print ("Completed: "+str(completed) + "/" + str(len(files)))
    out.flush()
out.close()
