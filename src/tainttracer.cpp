/*
 * Copyright 2014 James Ritchey
 * GNU GPLv3
 * 
 */
#include "pin.H"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <set>
#include <map>
#include <stdint.h>
#include <sstream>
#include <ctime>
#include <cstdlib>

extern "C" {
	#include "xed-interface.h"
	#include "xed-flags.h"
	#include "xed-types.h"
	#include "xed-portability.h"
	#include "xed-flag-enum.h"
	#include "xed-flag-action-enum.h"
	#include "xed-gen-table-defs.h"
}

namespace WINDOWS
{
	#pragma comment (lib, "WS2_32.lib")
	#include <Winsock2.h>
	#include <ws2tcpip.h>
	#include<Windows.h>

	typedef struct _IO_STATUS_BLOCK {
		union {
			NTSTATUS Status;
			PVOID Pointer;
		};
		ULONG_PTR Information;
	} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

	typedef VOID(WINAPI *PIO_APC_ROUTINE) (
		IN PVOID ApcContext,
		IN PIO_STATUS_BLOCK IoStatusBlock,
		IN ULONG Reserved
		);
		
}	

#define BUFSIZE							1024
#define STATUS_ACCESS_VIOLATION			0xc0000005
#define STATUS_STACK_BUFFER_OVERRUN		0xc0000409
#define BREAKPOINT 						0x80000003
#define GUARD_PAGE						0x80000001
#define SINGLE_STEP						0x80000004
#define CONTEXT_CONTROL                 0x00010001
#define CONTEXT_INTEGER                 0x00010002
#define CONTEXT_SEGMENTS                0x00010004
#define CONTEXT_FULL                    0x00010007
#define CONTEXT_DEBUG_REGISTERS         0x00010010

xed_state_t xedstate;
static bool canstartimplicit = false; // Bool for if can start implicit tainting, only after first tainted flag is read
static int implicitcount=0;
std::ofstream TraceFile;
static stringstream outfilestream;

class ThreadInfo {
	public:
		struct taintedflagsinfo {
			unsigned int flags;
			unsigned int value;
		};
		struct taintedregsinfo {
			unsigned int value;
		};
		set<REG> readreg; // read registers for this address, use xed to get which registers
		set<REG> writtenreg; //written registers for this address, use xed to get which registers
		set<unsigned int>memoryaddressesread; // address read, and length
		set<unsigned int>memoryaddresseswritten; // address written, and length
		bool flagsw; 
		bool flagsr; 
		xed_flag_set_t readflags; 
		xed_flag_set_t writtenflags; 
		char instmap[50]; //disassembly for this address
		bool istainted;
		bool decoded;
		unsigned char itext[XED_MAX_INSTRUCTION_BYTES]; // hex opcodes
		xed_decoded_inst_t decodedinstruction;
		IMG img; //module which this address belongs
		RTN rtn; // routine that the instruction is on
		map<REG, taintedregsinfo *> taintedregs; // current map of tainted registers for a thread, [reg][value]
		taintedflagsinfo taintedflags; // current map of tainted flags for a thread id, [tainted flags][flag value]
		
		ThreadInfo()
		{
			istainted=false;
			decoded=false;
			flagsr=false;
			flagsw=false;
			taintedflags.flags = 0;
			taintedflags.value = 0;
		}
		
		void clean()
		{
			istainted=false;
			decoded=false;
			flagsr=false;
			flagsw=false;
			readreg.clear();
			writtenreg.clear();
			memoryaddressesread.clear();
			memoryaddresseswritten.clear();
		}
		
		string ImgToString()
		{
			string imgname;		
			if (IMG_Valid(img))
				imgname = IMG_Name(img);
			else
				imgname = "Unknown";	
			return imgname;
		}
		
		string RtnToString()
		{
			string rtnname;
			if (RTN_Valid(rtn))
				rtnname = RTN_Name(rtn);
			else
				rtnname="Unknown";
			return rtnname;
		}
		
		void addRegs(REG reg, bool isread)
		{
			if (isread)
			{
				switch (reg)
				{
					case REG_EAX:
						readreg.insert(REG_AH);
						readreg.insert(REG_AL);
						readreg.insert(REG_AX);
						break;
					case REG_AX:
						readreg.insert(REG_AH);
						readreg.insert(REG_AL);
						readreg.insert(REG_EAX);
						break;
					case REG_AH:
					case REG_AL:
						readreg.insert(REG_AX);
						readreg.insert(REG_EAX);
						break;
					case REG_EBX:
						readreg.insert(REG_BH);
						readreg.insert(REG_BL);
						readreg.insert(REG_BX);
						break;
					case REG_BX:
						readreg.insert(REG_BH);
						readreg.insert(REG_BL);
						readreg.insert(REG_EBX);
						break;
					case REG_BH:
					case REG_BL:
						readreg.insert(REG_BX);
						readreg.insert(REG_EBX);
						break;
					case REG_ECX:
						readreg.insert(REG_CH);
						readreg.insert(REG_CL);
						readreg.insert(REG_CX);
						break;
					case REG_CX:
						readreg.insert(REG_CH);
						readreg.insert(REG_CL);
						readreg.insert(REG_ECX);
						break;
					case REG_CH:
					case REG_CL:
						readreg.insert(REG_ECX);
						readreg.insert(REG_CX);
						break;
					case REG_EDX:
						readreg.insert(REG_DH);
						readreg.insert(REG_DL);
						readreg.insert(REG_DX);
						break;
					case REG_DX:
						readreg.insert(REG_DH);
						readreg.insert(REG_DL);
						readreg.insert(REG_EDX);
						break;
					case REG_DH:
					case REG_DL:
						readreg.insert(REG_DX);
						readreg.insert(REG_EDX);
						break;
					case REG_ESI:
						readreg.insert(REG_SI);
						break;
					case REG_SI:
						readreg.insert(REG_ESI);
						break;
					case REG_EDI:
						readreg.insert(REG_DI);
						break;
					case REG_DI:
						readreg.insert(REG_EDI);
						break;
					case REG_EBP:
						readreg.insert(REG_BP);
						break;
					case REG_BP:
						readreg.insert(REG_EBP);
						break;
					case REG_ESP:
						readreg.insert(REG_SP);
						break;
					case REG_SP:
						readreg.insert(REG_ESP);
						break;
					case REG_EIP:
						readreg.insert(REG_IP);
						break;
					case REG_IP:
						readreg.insert(REG_EIP);
						break;
					default:
						break;
				}
			}
			else // written regs
			{
				switch (reg)
				{
					case REG_EAX:
						writtenreg.insert(REG_AH);
						writtenreg.insert(REG_AL);
						writtenreg.insert(REG_AX);
						break;
					case REG_AX:
						writtenreg.insert(REG_AH);
						writtenreg.insert(REG_AL);
						writtenreg.insert(REG_EAX);
						break;
					case REG_AH:
					case REG_AL:
						writtenreg.insert(REG_AX);
						writtenreg.insert(REG_EAX);
						break;
					case REG_EBX:
						writtenreg.insert(REG_BH);
						writtenreg.insert(REG_BL);
						writtenreg.insert(REG_BX);
						break;
					case REG_BX:
						writtenreg.insert(REG_BH);
						writtenreg.insert(REG_BL);
						writtenreg.insert(REG_EBX);
						break;
					case REG_BH:
					case REG_BL:
						writtenreg.insert(REG_BX);
						writtenreg.insert(REG_EBX);
						break;
					case REG_ECX:
						writtenreg.insert(REG_CH);
						writtenreg.insert(REG_CL);
						writtenreg.insert(REG_CX);
						break;
					case REG_CX:
						writtenreg.insert(REG_CH);
						writtenreg.insert(REG_CL);
						writtenreg.insert(REG_ECX);
						break;
					case REG_CH:
					case REG_CL:
						writtenreg.insert(REG_ECX);
						writtenreg.insert(REG_CX);
						break;
					case REG_EDX:
						writtenreg.insert(REG_DH);
						writtenreg.insert(REG_DL);
						writtenreg.insert(REG_DX);
						break;
					case REG_DX:
						writtenreg.insert(REG_DH);
						writtenreg.insert(REG_DL);
						writtenreg.insert(REG_EDX);
						break;
					case REG_DH:
					case REG_DL:
						writtenreg.insert(REG_DX);
						writtenreg.insert(REG_EDX);
						break;
					case REG_ESI:
						writtenreg.insert(REG_SI);
						break;
					case REG_SI:
						writtenreg.insert(REG_ESI);
						break;
					case REG_EDI:
						writtenreg.insert(REG_DI);
						break;
					case REG_DI:
						writtenreg.insert(REG_EDI);
						break;
					case REG_EBP:
						writtenreg.insert(REG_BP);
						break;
					case REG_BP:
						writtenreg.insert(REG_EBP);
						break;
					case REG_ESP:
						writtenreg.insert(REG_SP);
						break;
					case REG_SP:
						writtenreg.insert(REG_ESP);
						break;
					case REG_EIP:
						writtenreg.insert(REG_IP);
						break;
					case REG_IP:
						writtenreg.insert(REG_EIP);
						break;
					default:
						break;
				}
			}
		}
		
		bool disassembleInst(unsigned int instructionpointer)
		{	
			if (xed_format_intel(&decodedinstruction, instmap, 50, instructionpointer))
			{
				return true;
			}
			return false;
		}
		
		bool decodeInstruction(unsigned int size)
		{
			xed_decoded_inst_zero_set_mode(&decodedinstruction, &xedstate);
			xed_error_enum_t e = xed_decode(&decodedinstruction, itext, XED_MAX_INSTRUCTION_BYTES);
			if ( e == XED_ERROR_NONE )
			{
				return true;
			}
			outfilestream <<"decode failure: " << xed_error_enum_t2str(e)<<endl;
			return false;	
		}
	
		unsigned int setInstructionTextOpcodes(unsigned int instructionpointer, unsigned int length)
		{
			return PIN_SafeCopy(itext, (unsigned int *)instructionpointer, length);
		}
	
		void setFlags(unsigned int instructionpointer)
		{
			if (xed_decoded_inst_uses_rflags(&decodedinstruction)) {
				unsigned int i, nflags;
				const xed_simple_flag_t* rfi = xed_decoded_inst_get_rflags_info(&decodedinstruction);
				if (xed_simple_flag_reads_flags(rfi)) {
					flagsr=true;
					PIN_SafeCopy(&readflags, xed_simple_flag_get_read_flag_set(rfi), sizeof(xed_flag_set_t));
				}
				if (xed_simple_flag_writes_flags(rfi)) {
					flagsw=true;
					PIN_SafeCopy(&writtenflags, xed_simple_flag_get_written_flag_set(rfi), sizeof(xed_flag_set_t));
				}
			}
		}

		void UpdateTaintedWrittenFlagsValues( const CONTEXT *ctx)
		{
			if (flagsw)
			{
				unsigned int wflags = xed_flag_set_mask((const xed_flag_set_t *)&writtenflags);
				unsigned int writtenvalues = (unsigned int)PIN_GetContextReg(ctx, REG_GFLAGS);
				unsigned int temp = ((~((~writtenvalues) & wflags)) &	taintedflags.value);
				// fix the 1s and finish
				taintedflags.value = ((writtenvalues & wflags) | temp);
			}
		}
		
		void UnTaintWrittenFlags()
		{
			if (flagsw)
			{
				unsigned int wflags = xed_flag_set_mask((const xed_flag_set_t *)&writtenflags);
				taintedflags.flags = (~wflags) & taintedflags.flags;
			}
		}

		void TaintWrittenFlags()
		{
			if (flagsw)
			{
				unsigned int wflags = xed_flag_set_mask((const xed_flag_set_t *)&writtenflags);
				unsigned int taintedandwrittenflags = taintedflags.flags & wflags;

				taintedflags.flags = taintedflags.flags | wflags;
			}
		}

		string TaintedAndReadFlagsToString(const CONTEXT *ctx)
		{
			stringstream result;

			if (flagsr)
			{
				unsigned int read = xed_flag_set_mask((const xed_flag_set_t *)&readflags);
				unsigned int readandtainted = taintedflags.flags & read;
				unsigned int readandnottainted = readandtainted ^ read;	
				unsigned int flagvalues = (unsigned int)PIN_GetContextReg((const CONTEXT *)ctx, REG_GFLAGS);
				
				char buf[500];
				xed_flag_set_print((const xed_flag_set_t *)&readandnottainted,buf,500);
				result <<hex<< readandnottainted << ":" << buf;
				
				if (readandtainted)
				{
					char buff[500];
					result << "[T ";
					xed_flag_set_print((const xed_flag_set_t *)&readandtainted,buff,500);
					result <<hex<< readandtainted << ":" << buff;
					result << "]";
				}
				result << ":Values:" <<hex<< flagvalues;
			}
			
			return result.str();
		}
		
		bool IsReadFlagsTainted()
		{
			if (flagsr)
			{
				unsigned int tempread = xed_flag_set_mask(&readflags);
				if (taintedflags.flags & tempread) 
				{
					canstartimplicit = true;
					return true;
				}
			}
			return false;
		}

		void UnTaintWrittenRegs()
		{
			set<REG>::iterator writtenregit = writtenreg.begin();
			for (; writtenregit != writtenreg.end();writtenregit++)
			{
				if (taintedregs.find(*writtenregit) != taintedregs.end())
				{
					delete taintedregs[(*writtenregit)];
					taintedregs.erase(*writtenregit);
				}
			}
		}

		void TaintWrittenRegisters(const CONTEXT *ctx)
		{
			set<REG>::iterator writtenregit = writtenreg.begin();
			for (; writtenregit != writtenreg.end();writtenregit++)
			{
				// do not taint the stack pointer register?
				if (REG_FullRegName(*writtenregit) == REG_STACK_PTR)
				{
					continue;
				}
				
				unsigned int val;
				if (!REG_is_fr_or_x87(REG_FullRegName(*writtenregit)))
				{
					val = (unsigned int)PIN_GetContextReg(ctx, REG_FullRegName(*writtenregit));
				} else
				{
					if (REG_is_fr_for_get_context(REG_FullRegName(*writtenregit)))
					{
						val = (unsigned int)PIN_GetContextReg(ctx, REG_FullRegName(*writtenregit));
					}
					else
					{
						val =0;
					}
				}

				// if the written register is not in the tainted set already, then add it there
				if (taintedregs.find((*writtenregit)) == taintedregs.end())
				{
					taintedregs.insert(pair<REG, taintedregsinfo *>(*writtenregit, new taintedregsinfo));
				}
				taintedregs[(*writtenregit)]->value = val;	
			}
		}

		string TaintedAndReadRegsToString(const CONTEXT *ctx)
		{
			stringstream result;
			set<REG>::iterator readregit = readreg.begin();
			//for each read register
			for (; readregit != readreg.end();readregit++)
			{
				// this can cause "duplicates" for nested registers
				result << REG_StringShort(*readregit);
				// if it's in list of tainted registers, show that it's tainted
				if (taintedregs.find(*readregit) != taintedregs.end())
				{
					result << "[T]";
				}
				result << ": ";
				
				if (REG_is_xmm(REG_FullRegName(*readregit)) || REG_is_ymm(REG_FullRegName(*readregit)) || REG_is_fr_or_x87(*readregit))
				{
					if (REG_is_fr_for_get_context(REG_FullRegName(*readregit)))
					{
						result <<hex<<(unsigned int)PIN_GetContextReg(ctx, REG_FullRegName(*readregit));
					}
					else
					{
						result << "can't get value";
					}
				}
				else
				{
					result <<hex<<(unsigned int)PIN_GetContextReg(ctx, REG_FullRegName(*readregit));
				}
				result << ": ";
			}
			
			return result.str();
		}
		
		string TaintedAndWrittenRegsToString(const CONTEXT *ctx)
		{
			stringstream result;
			set<REG>::iterator writtenregit = writtenreg.begin();
			//for each read register
			for (; writtenregit != writtenreg.end();writtenregit++)
			{
				// this can cause "duplicates" for nested registers
				result << REG_StringShort(*writtenregit);
				// if it's in list of tainted registers, show that it's tainted
				if (taintedregs.find(*writtenregit) != taintedregs.end())
				{
					result << "[T]";
				}
				result << ": ";
				
				if (REG_is_xmm(REG_FullRegName(*writtenregit)) || REG_is_ymm(REG_FullRegName(*writtenregit)) || REG_is_fr_or_x87(*writtenregit))
				{
					if (REG_is_fr_for_get_context(REG_FullRegName(*writtenregit)))
					{
						result <<hex<<(unsigned int)PIN_GetContextReg(ctx, REG_FullRegName(*writtenregit));
					}
					else
					{
						result << "can't get value";
					}
				}
				else
				{
					result <<hex<<(unsigned int)PIN_GetContextReg(ctx, REG_FullRegName(*writtenregit));
				}
				result << ": ";
			}
			
			return result.str();
		}
		

		bool IsReadRegistersTainted()
		{
			set<REG>::iterator readregit = readreg.begin();
			//for each read register
			for (; readregit != readreg.end();readregit++)
			{
				// if it's in list of tainted registers
				if (taintedregs.find(*readregit) != taintedregs.end())
				{
					return true;
				}
			}
			return false;
		}
};

struct taintedmeminfo {
	uint8_t value;
};

struct readinfo {
	WINDOWS::LONGLONG offset;
	bool gotread;
	unsigned int buffer;
	WINDOWS::PIO_STATUS_BLOCK Iosb;
	unsigned int length;
};

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "tainttracer.txt", "specify trace output file name");
KNOB<string> KnobFileRead(KNOB_MODE_WRITEONCE, "pintool",
    "f", "", "specify which file name to trace");
KNOB<string> KnobNetworkRead(KNOB_MODE_WRITEONCE, "pintool",
    "n", "", "specify which IP address to trace");
KNOB<unsigned int> KnobSleep(KNOB_MODE_WRITEONCE, "pintool",
    "s", "10000", "specify sleep for process in milliseconds");
KNOB<unsigned int> KnobOracle(KNOB_MODE_WRITEONCE, "pintool",
    "z", "0", "only as oracle 0 or 1"); // only check for fatal unhandled exception
KNOB<int> KnobImplicit(KNOB_MODE_WRITEONCE, "pintool",
    "i", "0", "specify how many levels of implicit taints (EIP taints), 0 Default only explicit, -1 is unlimited");
KNOB<int> KnobDereference(KNOB_MODE_WRITEONCE, "pintool",
    "d", "0", "specify whether to dereference read memory or not, 0 or 1; can cause crash");

static map<unsigned int, taintedmeminfo *>taintedmem; // current map of tainted memory with byte value
static map<unsigned int, ThreadInfo *> threadinfo; // per thread information
static string inputfilename = "filename";
static string inputipaddress = "ipaddress";
static bool checkingip=false;
static bool begintaint=false;
static map<unsigned int, struct readinfo *> treadinfo; // per thread read information
static unsigned int sleepthreadid;
static unsigned int onlyasoracle=0;
static unsigned int dereferencememory=0;

PIN_LOCK lock;

VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v) 
{
    PIN_GetLock(&lock, threadid+1);
    outfilestream << "thread begin " << threadid <<endl;
	threadinfo.insert(pair<unsigned int, ThreadInfo *>(threadid, new ThreadInfo()));
    PIN_ReleaseLock(&lock);
}

VOID ThreadFini(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v) 
{
    PIN_GetLock(&lock, threadid+1);
    outfilestream << "thread end "<<threadid<<" code " << code <<endl;
	delete threadinfo[threadid];
	threadinfo.erase(threadid);
    PIN_ReleaseLock(&lock);
	/*
	if (threadid == 0)
	{
		outfilestream << "main thread returned, stopping process"<<endl;
		if (outfilestream.rdbuf()->in_avail() != 0)
		{
			TraceFile << outfilestream.str();
			outfilestream.str("");
		}
		TraceFile.flush();
		TraceFile.close();
		PIN_ExitProcess(5);
	}
	*/
}

VOID BeforeUnhandledExceptionFilter(THREADID threadid, CHAR *name, WINDOWS::EXCEPTION_POINTERS *exceptionpointer)
{
    PIN_GetLock(&lock, threadid+1);
	
	outfilestream << "Unhandled Exception Thread "<<threadid;
	outfilestream << ": name "<<name;
	outfilestream << ": exception code "<<exceptionpointer->ExceptionRecord->ExceptionCode;
	outfilestream <<": Is not continuable? "<<exceptionpointer->ExceptionRecord->ExceptionFlags;
	outfilestream <<": address "<<exceptionpointer->ExceptionRecord->ExceptionAddress<<endl;
	
	for (int i=0;i<exceptionpointer->ExceptionRecord->NumberParameters;i++)
	{
		outfilestream <<"Exception param "<<i<<": "<<exceptionpointer->ExceptionRecord->ExceptionInformation[i]<<endl;
	}
	
	bool accessviolation=false;
	unsigned int crasheip=0;
	IMG cimg;
	string rtnname;
	string imgname;
	unsigned int imgaddress = 0;
	unsigned int crashrva = 0;
	
	switch (exceptionpointer->ExceptionRecord->ExceptionCode)
	{
		case STATUS_ACCESS_VIOLATION:
			outfilestream << "Access Violation"<<endl;
			for (int i=0;i<exceptionpointer->ExceptionRecord->NumberParameters;i++)
			{
				if (i == 0)
					if (exceptionpointer->ExceptionRecord->ExceptionInformation[i] == 0)
						outfilestream <<"Read exception"<<endl;
					else if (exceptionpointer->ExceptionRecord->ExceptionInformation[i] == 1)
						outfilestream <<"Write exception"<<endl;
					else
						outfilestream <<"Not read or write."<<endl;
				else if (i == 1)
					outfilestream <<"@ address : "<<exceptionpointer->ExceptionRecord->ExceptionInformation[i]<<endl;
				else
					outfilestream <<"Some extra data"<<endl;
			}
			accessviolation=true;
		case STATUS_STACK_BUFFER_OVERRUN:
			if (!accessviolation)
				outfilestream << "Status_Stack_buffer_overrun"<<endl;	
			if (exceptionpointer->ContextRecord->ContextFlags & CONTEXT_CONTROL)
			{
				outfilestream <<"EIP: " << exceptionpointer->ContextRecord->Eip<<endl;
				crasheip = exceptionpointer->ContextRecord->Eip;
				outfilestream <<"EBP: " << exceptionpointer->ContextRecord->Ebp<<endl;
				outfilestream <<"ESP: " << exceptionpointer->ContextRecord->Esp<<endl;
				outfilestream <<"EFlags: " << exceptionpointer->ContextRecord->EFlags<<endl;
				outfilestream <<"SegCs: " << exceptionpointer->ContextRecord->SegCs<<endl;
				outfilestream <<"SegSs: " << exceptionpointer->ContextRecord->SegSs<<endl;
			}
			if (exceptionpointer->ContextRecord->ContextFlags & CONTEXT_INTEGER)
			{
				outfilestream <<"ESI: " << exceptionpointer->ContextRecord->Esi<<endl;
				outfilestream <<"EDI: " << exceptionpointer->ContextRecord->Edi<<endl;
				outfilestream <<"Eax: " << exceptionpointer->ContextRecord->Eax<<endl;
				outfilestream <<"Ebx: " << exceptionpointer->ContextRecord->Ebx<<endl;
				outfilestream <<"Ecx: " << exceptionpointer->ContextRecord->Ecx<<endl;
				outfilestream <<"Edx: " << exceptionpointer->ContextRecord->Edx<<endl;
			}
			if (exceptionpointer->ContextRecord->ContextFlags & CONTEXT_SEGMENTS)
			{
				outfilestream <<"SegDs: " << exceptionpointer->ContextRecord->SegDs<<endl;
				outfilestream <<"SegEs: " << exceptionpointer->ContextRecord->SegEs<<endl;
				outfilestream <<"SegFs: " << exceptionpointer->ContextRecord->SegFs<<endl;
				outfilestream <<"SegGs: " << exceptionpointer->ContextRecord->SegGs<<endl;
			}
			
			PIN_LockClient();
			cimg = IMG_FindByAddress(crasheip);
			rtnname = RTN_FindNameByAddress(crasheip);
			PIN_UnlockClient();

			if (IMG_Valid(cimg))
			{
				imgname = IMG_Name(cimg);
				imgaddress = IMG_StartAddress(cimg);
				outfilestream << "IMG name:: "<<imgname <<endl;
				outfilestream << "IMG StartAddress: "<<imgaddress <<endl;
			}
			else
			{
				imgname = "Unknown";
				outfilestream << "IMG name:: "<<imgname <<endl;
				outfilestream << "IMG StartAddress: "<<imgaddress <<endl;
			}
			if (!rtnname.empty())
			{
				outfilestream <<"RTN name: "<<rtnname<<endl;
			}
			else
			{
				rtnname = "Unknown";
				outfilestream <<"RTN name: "<<rtnname<<endl;
			}
			crashrva = crasheip - imgaddress;
			outfilestream << "CrashRVA:: "<<crashrva<<endl;

			break;
		case SINGLE_STEP: 
			outfilestream <<"Single step"<<endl;
			break;
		case GUARD_PAGE: 
			outfilestream <<"Guard page"<<endl;
			break;
		case BREAKPOINT: 
			outfilestream <<"Breakpoint"<<endl;
			break;
		default:
			outfilestream <<"Unknown exception"<<endl;
			break;
	}

//	if (exceptionpointer->ExceptionRecord->ExceptionFlags) //if exception is non-continueable, then exit
	outfilestream << "Exception, exiting application"<<endl;

	if (outfilestream.rdbuf()->in_avail() != 0)
	{
		TraceFile << outfilestream.str();
		outfilestream.str("");
	}

    TraceFile.close();
	PIN_ReleaseLock(&lock);
	PIN_ExitProcess(3);
}

VOID BeforeWSARecv(THREADID tid, CHAR * name, int s, unsigned int buf, unsigned int bufcount, unsigned int length, int flags, WINDOWS::LPOVERLAPPED  lpOverlapped, WINDOWS::LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) 
{
	PIN_GetLock(&lock, tid+1);
    outfilestream << "Before: " << name << hex << s << ", " << buf << ", " << bufcount << ", "<<length<<", "<< flags<<", "<<lpOverlapped<<", "<<lpCompletionRoutine<< endl;
	PIN_ReleaseLock(&lock);
}

VOID AfterWSARecv(THREADID tid, CHAR * name, ADDRINT ret)
{
	PIN_GetLock(&lock, tid+1);
    outfilestream << "After: " << name << "  returns " <<hex<< ret << hex << endl;
	PIN_ReleaseLock(&lock);
}

VOID BeforeRecv(THREADID tid,CHAR * name, int s, unsigned int buf, int len, int flags) 
{
	PIN_GetLock(&lock, tid+1);
	struct WINDOWS::sockaddr_in sockname;
	int leng = sizeof(sockname);
	outfilestream << "TID "<<tid<< " Before: " << name << " " << hex << s << ", " << buf << ", " << len << ", "<< flags<< endl;
	if (WINDOWS::getpeername(s, (struct WINDOWS::sockaddr *)&sockname, &leng) == 0)
	{
		string temp(WINDOWS::inet_ntoa(sockname.sin_addr));
		outfilestream << "Peer name: " << temp <<endl;
		if (inputipaddress.compare(temp) == 0)
		{
			outfilestream << "Input IP address equals peer name, tainting " <<endl;
			
			if (treadinfo[tid])
				delete treadinfo[tid];
			struct readinfo *tem = new readinfo;
			tem->gotread=true;
			tem->offset = 0;
			tem->buffer = buf;
			treadinfo[tid]=tem;
		}
	}
	PIN_ReleaseLock(&lock);
}

VOID AfterRecv(THREADID tid, CHAR * name, ADDRINT ret)
{
	PIN_GetLock(&lock, tid+1);
	outfilestream << "TID: " << tid << " After: " << name << "  returns " << ret << endl;
	
	if (ret>0 && treadinfo[tid] && treadinfo[tid]->gotread)
	{
		outfilestream << "Recv on tid: " << tid<<endl;
		treadinfo[tid]->gotread = false;
		treadinfo[tid]->length = ret;
		
		outfilestream << "Read length: " << treadinfo[tid]->length<<endl;
		outfilestream << "Read data: " << (char *)treadinfo[tid]->buffer<<endl;
		for (unsigned int i=0; i <  treadinfo[tid]->length ;i++) 
		{
			if (taintedmem.find( (unsigned int)treadinfo[tid]->buffer + i) == taintedmem.end()) 
				taintedmem.insert(pair<unsigned int, taintedmeminfo *>(treadinfo[tid]->buffer+i, new taintedmeminfo));
				
			taintedmem[(unsigned int) treadinfo[tid]->buffer+i]->value = *(uint8_t *)treadinfo[tid]->buffer+i;
		}
		begintaint=true;
	}
	
	PIN_ReleaseLock(&lock);
}

VOID BeforeReadFile(THREADID tid, CHAR * name, WINDOWS::HANDLE hFile, WINDOWS::LPVOID lpBuffer, WINDOWS::DWORD nNumberOfBytesToRead, WINDOWS::LPDWORD lpNumberOfBytesRead, WINDOWS::LPOVERLAPPED lpOverlapped) 
{
	PIN_GetLock(&lock, tid+1);
	char Path[BUFSIZE];

    outfilestream << "TID "<<tid<< " Before: " << name << hFile << ", " << lpBuffer << ", " << nNumberOfBytesToRead << ", "<< lpNumberOfBytesRead <<", " << lpOverlapped << hex << endl;
	if (WINDOWS::GetFinalPathNameByHandle(hFile, Path, BUFSIZE, 0) < BUFSIZE)
	{
		outfilestream << "Name: " << Path<<endl;
		string tempstr(Path);
		if (tempstr.find(inputfilename) != string::npos)
		{
		// assign buffer and number of bytes read
		// set received read as true
		}
	}

	PIN_ReleaseLock(&lock);
}

VOID AfterReadFile(THREADID tid, CHAR * name, ADDRINT ret)
{
	PIN_GetLock(&lock, tid+1);

    outfilestream << "TID "<<tid<< " After: " << name << "  returns " << hex << ret << endl;
	
	// if got read
		// set tainted memory
	
	PIN_ReleaseLock(&lock);
}

pair<unsigned int, unsigned int> StackRange(CONTEXT *ctx)
{
	unsigned int fs = (unsigned int)PIN_GetContextReg(ctx, REG_SEG_FS_BASE);
	unsigned int topofstack = *(unsigned int *)(fs +4);
	unsigned int bottomofstack = *(unsigned int *)(fs + 8);
	return make_pair<unsigned int, unsigned int>(topofstack, bottomofstack);
}

void UnwindStack(CONTEXT *ctx)
{
	pair<unsigned int, unsigned int> stackrange = StackRange(ctx);
	unsigned int ebpframe = (unsigned int)PIN_GetContextReg(ctx, REG_EBP);
	unsigned int top = get<0>(stackrange);
	unsigned int bottom = get<1>(stackrange);
	outfilestream << "Stack Trace: " << ebpframe<<endl;
	
	while(ebpframe)
	{
		if (ebpframe & 3)
			break; // not dword aligned
		unsigned int returnaddr = *(unsigned int *)(ebpframe + 4);
		PIN_LockClient();
		IMG frameimage = IMG_FindByAddress(returnaddr);
		string framertn = RTN_FindNameByAddress(returnaddr);
		PIN_UnlockClient();
		string imgname;
		outfilestream <<"Return address: " << returnaddr<< " ";
		if (IMG_Valid(frameimage))
		{
			imgname = IMG_Name(frameimage);
			outfilestream << "Image: " << imgname << " ";
		}
		else
		{
			outfilestream<< "image invalid "<<" ";
			break; // image invalid
		}
		outfilestream << "RTN: " << framertn<<endl;
		
		unsigned int nextframe = *(unsigned int *)(ebpframe);
		if (nextframe <= ebpframe)
			break; // next frame is lower than this one
		ebpframe = nextframe;
	}
}

VOID BeforeNtReadFile(THREADID tid, CHAR * name, WINDOWS::HANDLE FileHandle, WINDOWS::HANDLE Event, WINDOWS::PIO_APC_ROUTINE ApcRoutine, 
	WINDOWS::PVOID ApcContext, WINDOWS::PIO_STATUS_BLOCK IoStatusBlock, WINDOWS::PVOID Buffer, WINDOWS::ULONG Length, WINDOWS::PLARGE_INTEGER ByteOffset, WINDOWS::PULONG Key)
{
	PIN_GetLock(&lock, tid+1);

   	char Path[BUFSIZE];

	outfilestream << "TID "<< tid<< " Before: " << name<<  " FileHandle: " <<FileHandle << " Event: " <<Event<< " ApcRoutine: " << ApcRoutine << " ApcContext: " << ApcContext
				<< " IoStatusBlock: "<< IoStatusBlock << " Buffer: " << Buffer << " Length: "<<Length<< " ByteOffset: "	<< ByteOffset << " Key: "<< Key << endl;
	if (ByteOffset)
	{
		outfilestream << "*ByteOffset: " << ByteOffset->QuadPart <<endl;
	}
	if (WINDOWS::GetFinalPathNameByHandle(FileHandle, Path, BUFSIZE, 0) < BUFSIZE)
	{
		outfilestream << "Name: " << Path<<endl;
		string tempstr(Path);
		if (tempstr.find(inputfilename) != string::npos)
		{
			if (treadinfo[tid])
				delete treadinfo[tid];
			struct readinfo *tem = new readinfo;
			tem->gotread=true;
			if (ByteOffset)
				tem->offset = ByteOffset->QuadPart;
			else
				tem->offset = 0;
			tem->Iosb = IoStatusBlock;
			tem->buffer = (unsigned int)Buffer;
			treadinfo[tid]=tem;
		}
	}
	PIN_ReleaseLock(&lock);
}

VOID AfterNtReadFile(THREADID tid, CHAR * name, ADDRINT ret)
{
	PIN_GetLock(&lock, tid+1);
	outfilestream << "After: " << name << "  returns " << hex << ret << endl;
	if (ret==0 && treadinfo[tid] && treadinfo[tid]->gotread)
	{
		outfilestream << "Read on tid: " << tid<<endl;
		treadinfo[tid]->gotread = false;
		if (treadinfo[tid]->Iosb->Information > 0) // if read length is greater than 0
		{
			outfilestream << "File offset: " << treadinfo[tid]->offset<<endl;
			outfilestream << "Read status: " << treadinfo[tid]->Iosb->Status<<endl;
			outfilestream << "Read length: " << treadinfo[tid]->Iosb->Information<<endl;
			outfilestream << "Read data: " << (char *)treadinfo[tid]->buffer<<endl;
			for (unsigned int i=0; i <  treadinfo[tid]->Iosb->Information ;i++) 
			{
				if (taintedmem.find( (unsigned int)treadinfo[tid]->buffer + i) == taintedmem.end()) 
					taintedmem.insert(pair<unsigned int, taintedmeminfo *>(treadinfo[tid]->buffer+i, new taintedmeminfo));
					
				taintedmem[(unsigned int) treadinfo[tid]->buffer+i]->value = *(uint8_t *)treadinfo[tid]->buffer+i;
			}
			begintaint=true;
		}
	}
	PIN_ReleaseLock(&lock);
}

VOID BeforeIsDebuggerPresent(THREADID tid,CHAR * name) 
{
   PIN_GetLock(&lock, tid+1);

    outfilestream << "TID "<<tid<< " Before: " << name << endl;

	PIN_ReleaseLock(&lock);
}

VOID AfterIsDebuggerPresent(THREADID tid, CHAR * name, ADDRINT ret, CONTEXT *ctx)
{
	PIN_GetLock(&lock, tid+1);
	unsigned int eax = (unsigned int)PIN_GetContextReg(ctx, REG_EAX);
	unsigned int eip = (unsigned int)PIN_GetContextReg(ctx, REG_EIP);

    outfilestream << "After: " << name << "  returns " << hex << ret << " EAX: " <<eax<< " EIP: " <<eip<< " replacement function failed" << endl;

	PIN_ReleaseLock(&lock);
	PIN_SetContextReg(ctx, REG_EAX, 0);
	PIN_ExecuteAt((const CONTEXT *)ctx);
}   

WINDOWS::BOOL MyIsDebuggerPresent(THREADID tid, AFUNPTR orig)
{
	PIN_GetLock(&lock, tid+1);
	outfilestream << "MyIsDebuggerPresent: " << "TID: " << tid << " Original function: " <<orig<<endl;
	PIN_ReleaseLock(&lock);
	return 0;
}

void UnTaintWrittenMemory(THREADID tid)
{
	set<unsigned int>::iterator writtenmemit;
	for (writtenmemit=threadinfo[tid]->memoryaddresseswritten.begin();writtenmemit != threadinfo[tid]->memoryaddresseswritten.end();writtenmemit++)
	{
		map<unsigned int, taintedmeminfo *>::iterator taintedit;	
		taintedit = taintedmem.find(*writtenmemit);
		//if it's in the tainted set, remove it
		if (taintedit != taintedmem.end())
		{
			delete taintedmem[taintedit->first];
			taintedmem.erase(taintedit);
		}
	}
}

void TaintWrittenMemory(THREADID tid)
{
	set<unsigned int>::iterator writtenmemit;
	for (writtenmemit=threadinfo[tid]->memoryaddresseswritten.begin();writtenmemit != threadinfo[tid]->memoryaddresseswritten.end();writtenmemit++)
	{
		if (taintedmem.find(*writtenmemit) == taintedmem.end())
		{	
			taintedmem.insert(pair<unsigned int, taintedmeminfo *>(*writtenmemit, new taintedmeminfo));			
		}
		taintedmem[*writtenmemit]->value = *(uint8_t *)(*writtenmemit);	
	}
}

string TaintedAndReadMemoryToString(THREADID tid)
{
	stringstream result;
	set<unsigned int>::iterator readmemit;
	for (readmemit=threadinfo[tid]->memoryaddressesread.begin();readmemit != threadinfo[tid]->memoryaddressesread.end();readmemit++)
	{
		result <<hex<< *readmemit << " ";
		if ( taintedmem.find(*readmemit) != taintedmem.end())
		{
			result << "[T] ";
		}
		if (dereferencememory)
			result << " value "<<hex<< (int) (*(uint8_t *)(*readmemit)) << " ";
	}
	result << ":";
	
	return result.str();
}

bool IsReadMemoryTainted(THREADID tid)
{
	set<unsigned int>::iterator readmemit;
	for (readmemit=threadinfo[tid]->memoryaddressesread.begin();readmemit != threadinfo[tid]->memoryaddressesread.end();readmemit++)
	{
		if ( taintedmem.find(*readmemit) != taintedmem.end())
		{
			return true;
		}
	}
	return false;
}

bool IsImplicitTainted(THREADID tid)
{
	if (((implicitcount > 0) && canstartimplicit) || implicitcount == -1)
	{
		//if ((threadinfo[tid]->taintedregs.find(REG_EIP) != threadinfo[tid]->taintedregs.end()))
		//{
			implicitcount--;
			return true;
		//}
	}
	return false;
}

VOID Image(IMG img, VOID *v)
{
	if (outfilestream.rdbuf()->in_avail() != 0)
	{
		outfilestream.flush();
		TraceFile << outfilestream.str();
		TraceFile.flush();
		outfilestream.str("");
	}
	if (IMG_Valid(img))
	{
		outfilestream << "Image loaded: " <<IMG_Name(img) << " at "<<IMG_StartAddress(img)<<endl;
	}

    for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym))
    {
        string function = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY);
		
		if (!onlyasoracle)
		{	
			if (checkingip)
			{
				if (function == "recv")
				{
					RTN recvRtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));
					
					if (RTN_Valid(recvRtn))
					{
						outfilestream<<"Recv loaded"<<endl;
						RTN_Open(recvRtn);
						
						RTN_InsertCall(recvRtn, IPOINT_BEFORE, (AFUNPTR)BeforeRecv,
												IARG_THREAD_ID,
												IARG_ADDRINT, "recv",
												IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
												IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
												IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
												IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
												IARG_END);
						RTN_InsertCall(recvRtn, IPOINT_AFTER, (AFUNPTR)AfterRecv,
												IARG_THREAD_ID,
												IARG_ADDRINT, "recv",
												IARG_FUNCRET_EXITPOINT_VALUE,
												IARG_END);
						RTN_Close(recvRtn);
					}
				} 
			}
			
			/*
			if (function == "ReadFile")
			{
				RTN readfileRtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));
				
				if (RTN_Valid(readfileRtn))
				{
					outfilestream<<"ReadFile loaded"<<endl;
					RTN_Open(readfileRtn);
					
					RTN_InsertCall(readfileRtn, IPOINT_BEFORE, (AFUNPTR)BeforeReadFile,
											IARG_THREAD_ID,
											IARG_ADDRINT, "ReadFile",
											IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
											IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
											IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
											IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
											IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
											IARG_END);
					RTN_InsertCall(readfileRtn, IPOINT_AFTER, (AFUNPTR)AfterReadFile,
											IARG_THREAD_ID,
											IARG_ADDRINT, "ReadFile",
											IARG_FUNCRET_EXITPOINT_VALUE,
											IARG_END);
					RTN_Close(readfileRtn);
				}
			}
			*/
			if (!checkingip)
			{
				if (function == "ZwReadFile")
				{
					RTN readfileRtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));
					
					if (RTN_Valid(readfileRtn))
					{
						outfilestream<<"ZwReadFile loaded"<<endl;
						RTN_Open(readfileRtn);
						
						RTN_InsertCall(readfileRtn, IPOINT_BEFORE, (AFUNPTR)BeforeNtReadFile,
													IARG_THREAD_ID,
													IARG_ADDRINT, "ZwReadFile",
													IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
													IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
													IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
													IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
													IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
													IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
													IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
													IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
													IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
													IARG_END);
						RTN_InsertCall(readfileRtn, IPOINT_AFTER, (AFUNPTR)AfterNtReadFile,
													IARG_THREAD_ID,
													IARG_ADDRINT, "ZwReadFile",
													IARG_FUNCRET_EXITPOINT_VALUE,
													IARG_END);
						
						RTN_Close(readfileRtn);
					}
				}		
			}
			/*
			if (function == "WSARecv")
			{
				RTN recvRtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));
				
				if (RTN_Valid(recvRtn))
				{
					outfilestream<<"WSARecv loaded"<<endl;
					RTN_Open(recvRtn);
					
					RTN_InsertCall(recvRtn, IPOINT_BEFORE, (AFUNPTR)BeforeWSARecv,
											IARG_ADDRINT, "WSARecv",
											IARG_THREAD_ID,
											IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
											IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
											IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
											IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
											IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
											IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
											IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
											IARG_END);
					RTN_InsertCall(recvRtn, IPOINT_AFTER, (AFUNPTR)AfterWSARecv,
											IARG_THREAD_ID,
											IARG_ADDRINT, "WSARecv",
											IARG_FUNCRET_EXITPOINT_VALUE,
											IARG_END);	
					RTN_Close(recvRtn);
				}
			}
			*/
		}
		
		if (function == "UnhandledExceptionFilter")
		{
			RTN raiseexcept = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));
			if (RTN_Valid(raiseexcept))
			{	
				outfilestream << "UnhandledExceptionFilter loaded"<<endl;
				RTN_Open(raiseexcept);
				RTN_InsertCall(raiseexcept, IPOINT_BEFORE, (AFUNPTR)BeforeUnhandledExceptionFilter,
											IARG_THREAD_ID,
											IARG_ADDRINT, "UnhandledExceptionFilter",
											IARG_FUNCARG_ENTRYPOINT_VALUE, 0,	
											IARG_END);
				RTN_Close(raiseexcept);
			}
		}
		
		/*
		if (function == "IsDebuggerPresent")
        {
            RTN isdebuggerpresent = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));
            PROTO proto = PROTO_Allocate(PIN_PARG(WINDOWS::BOOL), CALLINGSTD_DEFAULT, "MyIsDebuggerPresent", PIN_PARG_END());
            if (RTN_Valid(isdebuggerpresent))
            {
				outfilestream<<"IsDebuggerPresent loaded, instrumenting, and replacing"<<endl;
                RTN_Open(isdebuggerpresent);
                
                RTN_InsertCall(isdebuggerpresent, IPOINT_BEFORE, (AFUNPTR)BeforeIsDebuggerPresent,
													IARG_THREAD_ID,
													IARG_ADDRINT, "IsDebuggerPresent",
													IARG_END);
                RTN_InsertCall(isdebuggerpresent, IPOINT_AFTER, (AFUNPTR)AfterIsDebuggerPresent,
													IARG_THREAD_ID,
													IARG_ADDRINT, "IsDebuggerPresent",
													IARG_FUNCRET_EXITPOINT_VALUE,
													IARG_CONTEXT,
													IARG_END);
                
                RTN_Close(isdebuggerpresent);
				AFUNPTR old = RTN_ReplaceSignature(isdebuggerpresent, AFUNPTR(MyIsDebuggerPresent), IARG_PROTOTYPE, proto, IARG_THREAD_ID, IARG_ORIG_FUNCPTR, IARG_END);	
            }
			PROTO_Free(proto);
        }
		*/
    }
}

VOID BuildMemRead(unsigned int addr, unsigned int size, THREADID tid)
{
	PIN_GetLock(&lock, tid+1);
	for (unsigned int i = addr; i<addr + size;i++)
	{
		threadinfo[tid]->memoryaddressesread.insert(i);
	}
	
	PIN_ReleaseLock(&lock);
}

VOID BuildReadReg(THREADID tid, REG reg)
{
	PIN_GetLock(&lock, tid+1);
	
	threadinfo[tid]->readreg.insert(reg);
	threadinfo[tid]->addRegs(reg, true);
	
	PIN_ReleaseLock(&lock);
}

VOID BuildWrittenMemory(unsigned int addr, unsigned int size, THREADID tid)
{
	PIN_GetLock(&lock, tid+1);
	for (unsigned int i = addr; i < addr + size;i++)
	{
		threadinfo[tid]->memoryaddresseswritten.insert(i);
	}
	PIN_ReleaseLock(&lock);
}

VOID BuildWrittenReg(unsigned int addr, THREADID tid, REG reg)
{
	PIN_GetLock(&lock, tid+1);
	threadinfo[tid]->writtenreg.insert(reg);
	threadinfo[tid]->addRegs(reg, false);
	
	PIN_ReleaseLock(&lock);
}

VOID Taint(THREADID tid, unsigned int ip, const CONTEXT *ctx)
{
	PIN_GetLock(&lock, tid+1);
		
	if (IsReadMemoryTainted(tid) || threadinfo[tid]->IsReadRegistersTainted() || threadinfo[tid]->IsReadFlagsTainted() || IsImplicitTainted(tid))
	{
		threadinfo[tid]->istainted=true;
		outfilestream << "TID: " <<hex<< tid;
		outfilestream << ":IP: " <<hex<< ip;
		outfilestream << ":Disasm " << threadinfo[tid]->instmap;
		outfilestream << ":IMG: " << threadinfo[tid]->ImgToString();
		outfilestream << ":RTN: " << threadinfo[tid]->RtnToString();
		outfilestream << ":Read Regs: " << threadinfo[tid]->TaintedAndReadRegsToString(ctx);
		outfilestream << ":Read Flags: " << threadinfo[tid]->TaintedAndReadFlagsToString(ctx);
		outfilestream << ":Read Memory: "<< TaintedAndReadMemoryToString(tid) <<endl;	
	//	outfilestream << ":Written Regs: " << threadinfo[tid]->TaintedAndWrittenRegsToString(ctx) <<endl;
		
		TaintWrittenMemory(tid);
		threadinfo[tid]->TaintWrittenFlags(); // will update flag values after instruction is executed
		threadinfo[tid]->TaintWrittenRegisters(ctx);
	}
	else
	{
		UnTaintWrittenMemory(tid);
		threadinfo[tid]->UnTaintWrittenFlags();
		threadinfo[tid]->UnTaintWrittenRegs();
	}
	
	if (outfilestream.rdbuf()->in_avail() != 0)
	{
		outfilestream.flush();
		TraceFile << outfilestream.str();
		TraceFile.flush();
		outfilestream.str("");
	}
	
	PIN_ReleaseLock(&lock);
}

VOID RegWriteAfter(THREADID tid,const CONTEXT *ctx)
{
	PIN_GetLock(&lock, tid+1);
	
	threadinfo[tid]->UpdateTaintedWrittenFlagsValues(ctx);

	PIN_ReleaseLock(&lock);
}

VOID cleanAndDecode(unsigned int ip, THREADID tid, unsigned int instructionlength)
{
	PIN_GetLock(&lock, tid+1);
	
	if (outfilestream.rdbuf()->in_avail() != 0)
	{
		outfilestream.flush();
		TraceFile << outfilestream.str();
		TraceFile.flush();
		outfilestream.str("");
	}
	
	threadinfo[tid]->clean();
	
	PIN_LockClient();
	threadinfo[tid]->img = IMG_FindByAddress(ip);
	threadinfo[tid]->rtn = RTN_FindByAddress(ip);
	PIN_UnlockClient();
	
	threadinfo[tid]->setInstructionTextOpcodes(ip, instructionlength);
	
	if (threadinfo[tid]->decodeInstruction(instructionlength))
	{	
		//outfilestream << "decoded ok ";
		if (threadinfo[tid]->disassembleInst(ip))
		{
		//	outfilestream << "disassembly ok";
			// decoded fine
		}
		threadinfo[tid]->setFlags(ip);
	}
	
	PIN_ReleaseLock(&lock);
}

//for each instruction
VOID EachInstruction(INS ins, VOID *v)
{
	if (begintaint) 
	{ 
		INS_InsertCall(
				ins, 
				IPOINT_BEFORE, 
				(AFUNPTR)cleanAndDecode, 
				IARG_INST_PTR,
				IARG_THREAD_ID, 
				IARG_UINT32, 
				INS_Size(ins),
				IARG_END);
	
		UINT32 memOperands = INS_MemoryOperandCount(ins);
		//build memory read, reg read, memory write, reg write	
		for (UINT32 memOp = 0; memOp < memOperands; memOp++)
		{   
			if (INS_MemoryOperandIsRead(ins, memOp))
			{   
				INS_InsertPredicatedCall(
					ins, 
					IPOINT_BEFORE, 
					(AFUNPTR)BuildMemRead,
					IARG_MEMORYOP_EA, 
					memOp,
					IARG_MEMORYREAD_SIZE,
					IARG_THREAD_ID,
					IARG_END);
			}   
		}
		
		//Build read registers
		// Handle Stack pointer read on push?
		for (UINT32 r=0; r<INS_MaxNumRRegs(ins);r++) 
		{
				// REG c = INS_RegR(ins, r);	
				// There is read EIP on branch/call instructions
				// may need to reverse this
				if (!(INS_IsBranchOrCall(ins) && (INS_RegR(ins, r) == REG_EIP || INS_RegR(ins, r) == REG_IP)))
				{					
					INS_InsertCall(
					ins, IPOINT_BEFORE, 
					(AFUNPTR)BuildReadReg,
					IARG_THREAD_ID,
					IARG_UINT32,
					INS_RegR(ins, r),
					IARG_END);
				}
		}

		//Build written memory
		for (UINT32 memOp = 0; memOp < memOperands; memOp++)
		{   
			if (INS_MemoryOperandIsWritten(ins, memOp))
			{   
				INS_InsertPredicatedCall(
							ins, 
							IPOINT_BEFORE, 
							(AFUNPTR)BuildWrittenMemory,
							IARG_MEMORYOP_EA, 
							memOp,
							IARG_MEMORYWRITE_SIZE,
							IARG_THREAD_ID,
							IARG_END);
			}
		}
		
		//Build written registers
		// Handle Stack pointer written on push?
		for (UINT32 r=0; r<INS_MaxNumWRegs(ins);r++)
		{
			INS_InsertCall(
				ins, 
				IPOINT_BEFORE, 
				(AFUNPTR)BuildWrittenReg,
				IARG_INST_PTR,
				IARG_THREAD_ID,
				IARG_UINT32,
				INS_RegW(ins, r),
				IARG_END);
		}
			
		// taint
		INS_InsertCall(
			ins, 
			IPOINT_BEFORE, 
			(AFUNPTR)Taint,
			IARG_THREAD_ID,
			IARG_INST_PTR,
			IARG_CONST_CONTEXT,
			IARG_END);
			
		//update the tainted values for FLAGS after instruction is executed
		if (INS_HasFallThrough(ins))
		{
			INS_InsertCall(
				ins, 
				IPOINT_AFTER, 
				(AFUNPTR)RegWriteAfter,
				IARG_THREAD_ID,
				IARG_CONST_CONTEXT,
				IARG_END);
		}
	}
}

VOID Fini(INT32 code, VOID *v)
{
	if (outfilestream.rdbuf()->in_avail() != 0)
	{
		TraceFile << outfilestream.str();
		outfilestream.str("");
	}
    TraceFile.close();
}

VOID ContextChange(THREADID threadid, CONTEXT_CHANGE_REASON reason, const CONTEXT *from, CONTEXT *to, INT32 info, VOID *v)
{
    PIN_GetLock(&lock, threadid+1);
	if (outfilestream.rdbuf()->in_avail() != 0)
	{
		outfilestream.flush();
		TraceFile << outfilestream.str();
		TraceFile.flush();
		outfilestream.str("");
	}
//	outfilestream << "Thread "<<threadid<< ": reason "<<reason<<endl;
	switch (reason)
	{
		case  CONTEXT_CHANGE_REASON_EXCEPTION:
			outfilestream << "TID: " << threadid << " Exception reason: " << " Exception code "<<info<< " Value: " << v <<endl;
			if ((info == STATUS_ACCESS_VIOLATION) || (info == STATUS_STACK_BUFFER_OVERRUN ))
				begintaint=false;
			break;
		case CONTEXT_CHANGE_REASON_CALLBACK:
			break;
		case CONTEXT_CHANGE_REASON_APC:
			break; 
		default:
			break;
	}

    PIN_ReleaseLock(&lock);
}
   
INT32 Usage()
{
    cerr << "This tool produces a taint trace" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

VOID timer(void *ar)
{
	WINDOWS::Sleep((WINDOWS::DWORD)ar);
	if (outfilestream.rdbuf()->in_avail() != 0)
	{
		TraceFile << outfilestream.str();
		outfilestream.str("");
	}
    TraceFile.close();
	PIN_ExitProcess(5);
}

/*
VOID SyscallEntry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v)
{
	PIN_GetLock(&lock, thread_id+1);
	if (PIN_GetSyscallNumber(ctx, std) == 0x3) // if read syscall
	{
		outfilestream << "system call: "<<PIN_GetSyscallNumber(ctx, std)<<", arguments:";
		for (int i=0;i<4;i++)
		{
			unsigned int value = PIN_GetSyscallArgument(ctx, std, i);
			outfilestream << value << " ";
		} 	 
		outfilestream<<endl;
		unsigned int buf = PIN_GetSyscallArgument(ctx, std, 1);
		outfilestream<<endl;
	}
	PIN_ReleaseLock(&lock);
}
*/
/*
VOID SyscallExit(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, void *v)
{
	PIN_GetLock(&lock, tid+1);

	unsigned int value = PIN_GetSyscallReturn(ctx, std);
	outfilestream << "return value: "<<value<<endl;
	
	PIN_ReleaseLock(&lock);
}
*/

int main(int argc, char *argv[])
{
    PIN_InitSymbols();
	
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }

	PIN_InitLock(&lock);
	unsigned int sleeptime = KnobSleep.Value();
	onlyasoracle = KnobOracle.Value();
	implicitcount = KnobImplicit.Value();
	inputfilename = KnobFileRead.Value();
	inputipaddress = KnobNetworkRead.Value();
	dereferencememory = KnobDereference.Value();
	
	if (!inputipaddress.empty())
	{
		checkingip=true;
	}
	else if (!inputfilename.empty())
	{
		checkingip=false;
	}
	else
	{
		cerr << "Must set input ipaddress or input filename"<<endl;
		return Usage();
	}
	
	xed_tables_init();
	xed_state_zero(&xedstate);
	xed_state_init2(&xedstate, XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b);
	
	if (sleeptime)
		sleepthreadid = PIN_SpawnInternalThread(timer, (void *)sleeptime, 0, NULL);

    TraceFile.open(KnobOutputFile.Value().c_str());
    outfilestream << setw(2) << setfill('0') << hex;
    TraceFile.setf(ios::showbase);
	outfilestream << "sleepthreadid: " <<sleepthreadid<<endl;
    
    IMG_AddInstrumentFunction(Image, 0);
    INS_AddInstrumentFunction(EachInstruction, 0);
    //PIN_AddSyscallEntryFunction(SyscallEntry, 0); 
    //PIN_AddSyscallExitFunction(SyscallExit, 0);
	PIN_AddThreadStartFunction(ThreadStart, 0); 
    PIN_AddThreadFiniFunction(ThreadFini, 0);
	PIN_AddContextChangeFunction(ContextChange, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();
    
    return 0;
}