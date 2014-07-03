# Copyright 2014 James Ritchey
# GNU GPLv3

#KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
#    "o", "tainttracer.txt", "specify trace output file name");
#KNOB<string> KnobFileRead(KNOB_MODE_WRITEONCE, "pintool",
#    "f", "", "specify which file name to trace");
#KNOB<string> KnobNetworkRead(KNOB_MODE_WRITEONCE, "pintool",
#    "n", "", "specify which IP address to trace");
#KNOB<unsigned int> KnobSleep(KNOB_MODE_WRITEONCE, "pintool",
#    "s", "10000", "specify sleep for process in milliseconds");
#KNOB<unsigned int> KnobOracle(KNOB_MODE_WRITEONCE, "pintool",
#    "z", "0", "only as oracle 0 or 1"); // only check for fatal unhandled exception
#KNOB<int> KnobImplicit(KNOB_MODE_WRITEONCE, "pintool",
#    "i", "0", "specify how many levels of implicit taints (EIP taints), 0 Default only explicit, -1 is unlimited");
#KNOB<int> KnobDereference(KNOB_MODE_WRITEONCE, "pintool",
#    "d", "0", "specify whether to dereference read memory or not, 0 or 1; can cause crash");

from pydbg import *
from pydbg.defines import *
import shutil
from datetime import datetime
import subprocess
import os
from os.path import join

sleeptime = 0													# how many milliseconds to sleep for
outputfile = r'C:\Users\user\Desktop\tainttracer.txt'		# output file information
program = r'C:\Program Files\DAEMON Tools Lite\DTLite.exe'		# program to start from beginning
service = r'DTLite.exe'			# service to attach to
inputfile = r''					# filter file read by file name
inputip = r'127.0.0.1'			# filter recv by peer IP address
crashdir = r'C:\newcrashes' 	# where to store crash information
implicit = 0					# how many implicit taints to do
doattach = True					# attach to program or start program from beginning
dereferencememory = 0			# whether to dereference read memory or not
pinbat = r'C:\Users\user\Downloads\pin-2.13-65163-msvc10-windows\pin-2.13-65163-msvc10-windows\pin_bat.bat'
pintool = r'C:\Users\user\Downloads\pin-2.13-65163-msvc10-windows\pin-2.13-65163-msvc10-windows\source\tools\ManualExamples\obj-ia32\tainttracer.dll'

def getTimeStamp():
	return datetime.now().strftime("%Y_%m_%d_%H_%M_%S")

def process(retv):
	if retv == 3:
		print " program crashed, now copying outfile: " + outputfile
		print " program name: " + os.path.basename(program)
		print " input file name: " + os.path.basename(inputfile)
		crashimage="UnknownImage"
		crashrva="UnknownCrashRVA"
		
		#get program name (without path), inputfile, parse crashed module, parse crash rva, get timestamp, write outfile and input crashfile
		try:
			f = open(outputfile, "r")
			for line in f:
				tokens = line.split("::", 2)
				if (len(tokens) == 2):
					name = tokens[0].lstrip().rstrip()
					value = tokens[1].lstrip().rstrip()
					if name == "IMG name":
						if value:
							print "IMG name is " + value
							crashimage = value
					elif name == "CrashRVA":
						if value:
							print "Crash RVA is " + value
							crashrva = value
		except IOError:
			print " Problems opening outputfile"
		finally:
			f.close()
		print "IMG: " + crashimage
		print "RVA: " + crashrva
		print "Input: " + os.path.basename(inputfile)
		print "Program: " + os.path.basename(program)
		try:
			os.makedirs(crashdir + "\\" + os.path.basename(program) + "\\" + os.path.basename(inputfile) + "\\" + os.path.basename(crashimage) + "\\" + crashrva)
		except Exception:
			print "Couldn't make directories, or already exists"
		try:
			filename, fileext = os.path.splitext(inputfile)
			print "name: " + filename
			print "ext: " + fileext
			print "inputfile: " + inputfile
			print "target: " + crashdir + "\\"+ os.path.basename(program) + "\\" + os.path.basename(inputfile) + "\\" + os.path.basename(crashimage) + "\\" + crashrva + "\\crashsynop_" + thetime + fileext

			shutil.copyfile(outputfile, crashdir + "\\"+ os.path.basename(program) + "\\" + os.path.basename(inputfile) + "\\" + os.path.basename(crashimage) + "\\" + crashrva + "\\crash_" + thetime + ".out")
		except IOError, (errno, strerror):
			print "Couldn't copy fuzzed filename to crash directory"
			print "%s %s" % (errno, strerror)
	elif retv == 5:
		print getTimeStamp()  + " program ended from timer"
	else:
		print getTimeStamp()  + " program ended naturally??"

# MAIN #
dbg = pydbg()
found = 0
for (pid, name) in dbg.enumerate_processes():
	if name == service:
		found=1
		break

print  getTimeStamp() + "executing pin tool"

if (doattach):
	if (found):
		returnv = subprocess.call(pinbat + ' -follow_execv -pid '+ str(pid) +' -t ' + pintool + ' -n ' + inputip + ' -d ' + str(dereferencememory) + ' -i ' + str(implicit) + ' -o ' + outputfile + ' -s ' + str(sleeptime) + ' --' , shell=True)
		thetime = getTimeStamp()
		print thetime + " return code " + str(returnv)
		process(returnv)
	else:
		print getTimeStamp() + " couldn't find service"
else:
	returnv = subprocess.call(pinbat + ' -follow_execv -t ' + pintool  + ' -n ' + inputip + ' -d ' + str(dereferencememory) + ' -i ' + str(implicit) + ' -s ' + str(sleeptime) + ' -o ' + outputfile + ' -- "' + program + '" ' + inputfile, shell=True)
	thetime = getTimeStamp()
	print thetime + " return code " + str(returnv)
	process(returnv)