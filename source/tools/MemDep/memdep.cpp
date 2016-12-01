//PIN
#include <pin.H>

//C/C++ std library
#include <iostream>
#include <fstream>
#include <type_traits>
#include <map>
#include <algorithm>
#include <deque>
#include <utility>
#include <cstring>
#include <memory>
#include <functional>
#include <io.h>
//PINCRT
#include <os-apis/process.h>
//#include "gnuplot-iostream.h"

//XED
extern "C" {
#include <xed-decode.h>
#include <xed-decoded-inst-api.h>
#include <xed-print-info.h>
}

//Windows
namespace NT {
#include <Windows.h>
#include <winternl.h>
	/*
	__kernel_entry NTSTATUS
		NTAPI NtDuplicateObject(
			_In_      HANDLE      SourceProcessHandle,
			_In_      HANDLE      SourceHandle,
			_In_opt_  HANDLE      TargetProcessHandle,
			_Out_opt_ PHANDLE     TargetHandle,
			_In_      ACCESS_MASK DesiredAccess,
			_In_      ULONG       HandleAttributes,
			_In_      ULONG       Options
	); 
	__kernel_entry NTSTATUS
		NTAPI NtOpenProcess(
			_Out_ PHANDLE ProcessHandle,
			_In_ ACCESS_MASK DesiredAccess,
			_In_ POBJECT_ATTRIBUTES ObjectAttributes,
			_In_opt_ PCLIENT_ID ClientId
		);
	*/
	static_assert(sizeof(ADDRINT) == sizeof(PVOID), "check pointer size");
}

struct MEM_ACCESS {
	struct {
		ADDRINT inst : sizeof(ADDRINT) * 8 - 1;
		ADDRINT rw : 1;
	};
	ADDRINT mem;
};

map<ADDRINT, string> img_infos;

struct TINFO{
	NT::NT_TIB tib;
	ADDRINT LastWrite;
	UINT32 WriteSize;
	ADDRINT StartSP;
	ADDRINT StartIP;
	deque<MEM_ACCESS> Traces;
	void add_trace(MEM_ACCESS acc) {
		if (acc.mem < (ADDRINT)tib.StackBase && acc.mem >= (ADDRINT)tib.StackLimit) {
			Traces.push_back(acc);
		}
	}
	void add_read(ADDRINT addr, ADDRINT inst, UINT32 size) {
		MEM_ACCESS access;
		access.inst = inst;
		access.rw = false;
		access.mem = addr;
		add_trace(access);
	}
	void add_write(ADDRINT addr, ADDRINT inst, UINT32 size) {
		MEM_ACCESS access;
		access.inst = inst;
		access.rw = true;
		access.mem = addr;
		add_trace(access);
	}
};

struct cFILE : FILE {
	~cFILE() {
		fclose(this);
	}
	static void operator delete(void* ptr, std::size_t sz)
	{}
	static void operator delete[](void* ptr, std::size_t sz)
	{}
};

struct AppProc {
	NT::HANDLE proc;
	NT::HANDLE input;
	auto_ptr<cFILE> f_input;
	AppProc(NT::DWORD pid, NT::HANDLE _input) {
		proc = NT::OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
		if (!proc)
			abort();
		if (!NT::DuplicateHandle(proc, _input, NT::GetCurrentProcess(), &input,
			0, FALSE, DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS))
			abort();
		f_input.reset(static_cast<cFILE*>(fdopen(reinterpret_cast<NATIVE_FD>(input), "w")));
	}
	struct AppFile {
		NT::HANDLE input; //HANDLE in current process
		NT::HANDLE output; //HANDLE in app process
		auto_ptr<cFILE> f;
		AppFile(NT::HANDLE _in, NT::HANDLE _out, cFILE* _f) :
			input(_in), output(_out), f(_f) {}
	};
	AppFile AllocInput() {
		NT::HANDLE in, out;
		if (!OS_RETURN_CODE_IS_SUCCESS(OS_Pipe(OS_PIPE_CREATE_FLAGS_NONE,
			reinterpret_cast<NATIVE_FD*>(&in),
			reinterpret_cast<NATIVE_FD*>(&out))))
			abort();
		if (!NT::DuplicateHandle(NT::GetCurrentProcess(), out, proc, &out,
			0, FALSE, DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS))
			abort();
		FILE* f = fdopen(reinterpret_cast<NATIVE_FD>(in), "w");
		return AppFile{ in, out, static_cast<cFILE*>(f) };
	}
};

static FILE* outstream = fopen("memdep.txt", "w");
static map<THREADID, TINFO> thread_infos;
static REG RegTinfo;
static REG RegScratch;

VOID ins_ana_nomem(TINFO* info, ADDRINT ip) {
}
VOID ins_ana_r(TINFO* info, ADDRINT ip, ADDRINT read, UINT32 rsize) {
	info->add_read(read, ip, rsize);
}
VOID ins_ana_rr(TINFO* info, ADDRINT ip, ADDRINT read, ADDRINT read2, UINT32 rsize) {
	info->add_read(read, ip, rsize);
	info->add_read(read2, ip, rsize);
}
VOID ins_ana_w(TINFO* info, ADDRINT ip, ADDRINT write, UINT32 wsize) {
	info->add_write(write, ip, wsize);
}
VOID ins_ana_rw(TINFO* info, ADDRINT ip, ADDRINT read, UINT32 rsize, ADDRINT write, UINT32 wsize) {
	info->add_read(read, ip, rsize);
	info->add_write(write, ip, wsize);
}
VOID ins_ana_rrw(TINFO* info, ADDRINT ip, ADDRINT read, ADDRINT read2, UINT32 rsize, ADDRINT write, UINT32 wsize) {
	info->add_read(read, ip, rsize);
	info->add_read(read2, ip, rsize);
	info->add_write(write, ip, wsize);
}

void print_addr_pretty(FILE* f, ADDRINT addr) {
	IMG img = IMG_FindByAddress(addr);
	RTN rtn = RTN_FindByAddress(addr);
	fprintf(f, "[%s!+%p]",
		IMG_Valid(img) ? IMG_Name(img).c_str() : "",
		IMG_Valid(img) ? (void*)(addr - IMG_StartAddress(img)) : (void*)addr);
	if (RTN_Valid(rtn))
		fprintf(f, " (%s+%p)",
			RTN_Name(rtn).c_str(),
			(void*)(addr - RTN_Address(rtn)));
}

struct PartialStr {
	const char* s;
};

bool operator< (const PartialStr& a, const string& b) {
	return _strnicmp(a.s, b.c_str(), b.size()) < 0;
}

bool operator< (const string& a, const PartialStr& b) {
	return _strnicmp(a.c_str(), b.s, a.size()) < 0;
}

bool img_excluded(IMG img) {
	if (!IMG_Valid(img))
		return false;
	return !IMG_IsMainExecutable(img);
	/*auto& name = IMG_Name(img);
	auto sep = name.find_last_of('\\');
	if (sep == string::npos)
		sep = 0;
	auto pre = name.c_str();
	auto suf = pre + sep;
	static const string prefix[] = {
		"C:\\Windows",
	};
	static const string suffix[] = {
		"icu",
		"msvc",
		"Qt",
	};
	return (binary_search(prefix + 0, prefix + sizeof(prefix) / sizeof(prefix[0]), PartialStr{ pre }) ||
		binary_search(suffix + 0, suffix + sizeof(suffix) / sizeof(suffix[0]), PartialStr{ suf }));*/
}

CHAR* parse_env(CHAR** env, const CHAR* match) {
	auto len = strlen(match);
	for (; *env && strncmp(*env, match, len); ++env);
	if (!*env)
		return nullptr;
	return *env + len + 1; //assume '=' must present
}

extern "C" {
}

static_assert(sizeof(NT::HANDLE) == sizeof(NATIVE_FD), "HANDLE and NATIVE_FD have different size");

AppProc* steal_gnuplot_handle() {
	static char _buf_gnuplot[sizeof(AppProc)];
	NATIVE_PID pid;
	CHAR** env;
	USIZE size;
	if (!OS_RETURN_CODE_IS_SUCCESS(OS_GetPid(&pid)) ||
		!OS_RETURN_CODE_IS_SUCCESS(OS_GetEnvironmentBlock(pid, &env, &size))) {
		abort();
	}
	const CHAR *s_app_pid, *s_app_pipe;
	NT::DWORD app_pid = 0;
	NT::HANDLE app_input = NULL;
	if ((s_app_pid = parse_env(env, "APP_PIPE_PID")) &&
		(sscanf(s_app_pid, "%lx", &app_pid) == 1) &&
		(s_app_pipe = parse_env(env, "APP_PIPE_HANDLE")) &&
		(sscanf(s_app_pipe, "%p", &app_input) == 1)) {
		return new (_buf_gnuplot)AppProc(app_pid, app_input);
	}
	return nullptr;
}
static AppProc* _app_gnuplot = steal_gnuplot_handle();

int main(int argc, char** argv){
	fprintf(_app_gnuplot->f_input.get(), "hello");
	_app_gnuplot->~AppProc();
	return 0;

	img_infos[0] = "NULL";

	PIN_InitSymbolsAlt(DEBUG_OR_EXPORT_SYMBOLS);
	PIN_Init(argc, argv);

	if (!REG_valid(RegTinfo = PIN_ClaimToolRegister()) || !REG_valid(RegScratch = PIN_ClaimToolRegister())) {
		cerr << "Cannot allocate a scratch register.\n" << flush;
		abort();
	}
	
	IMG_AddInstrumentFunction([](IMG img, VOID *) {
		img_infos[IMG_StartAddress(img)] = IMG_Name(img);
	}, NULL);


	PIN_AddThreadStartFunction([](THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)->VOID{
		auto* tib = (NT::PNT_TIB)NT::NtCurrentTeb();
		TINFO info;
		PIN_SafeCopy(&info.tib, tib, sizeof(*tib));
		info.StartSP = (ADDRINT)info.tib.StackBase;//PIN_GetContextReg(ctxt, REG_STACK_PTR);
		info.StartIP = PIN_GetContextReg(ctxt, REG_INST_PTR);
		//WIND::CONTEXT **pp_nt_cxt = (WIND::CONTEXT **)((void**)info.StartSP + 1);
		//WIND::CONTEXT *p_nt_cxt;
		//PIN_SafeCopy(&p_nt_cxt, pp_nt_cxt, sizeof(p_nt_cxt));
		//WIND::CONTEXT nt_cxt;
		//PIN_SafeCopy(&nt_cxt, p_nt_cxt, sizeof(nt_cxt));
		fprintf(outstream, "thread %d started, with sp_base = %p, sp_limit = %p, sp = %p, ip = %p ",
			(int)threadIndex,
			(void*)info.tib.StackBase,
			(void*)info.tib.StackLimit,
			(void*)info.StartSP,
			(void*)info.StartIP);
		print_addr_pretty(outstream, info.StartIP);
		/*RTN rtn = RTN_FindByAddress(info.StartIP);
		if (RTN_Valid(rtn) && !strcmp(RTN_Name(rtn).c_str(), "RtlUserThreadStart")) {
			fputs(" Entry = ", outstream);
			print_addr_pretty(outstream, nt_cxt.Eax);
		}*/
		fputc('\n', outstream);
		auto i = thread_infos.insert(make_pair(threadIndex, info));
		PIN_SetContextReg(ctxt, RegTinfo, reinterpret_cast<ADDRINT>(&i.first->second));
	}, NULL);

	PIN_AddThreadFiniFunction([](THREADID threadIndex, const CONTEXT *ctxt, INT32 code, VOID *v)->VOID{
		auto i = thread_infos.find(threadIndex);
		if (i != thread_infos.end()) {
			fprintf(outstream, "thread %d\n", (int)i->first);
			fputs("RW|Stack_Offset|Inst_Offset\n", outstream);
			for (auto& t : i->second.Traces) {
				IMG img = IMG_FindByAddress(t.inst);
				if (img_excluded(img))
					continue;
				//char buf[512];
				xed_uint8_t inst[15];
				PIN_SafeCopy(inst, (void*)t.inst, sizeof(inst));
				xed_decoded_inst_t xed_inst;
				xed_state_t state{ XED_MACHINE_MODE_LONG_COMPAT_32 , XED_ADDRESS_WIDTH_32b };
				xed_decoded_inst_zero_set_mode(&xed_inst, &state);
				xed_decode(&xed_inst, inst, sizeof(inst) / sizeof(inst[0]));
					//!xed_format_context(XED_SYNTAX_ATT, &xed_inst, buf, sizeof(buf)/sizeof(buf[0]), t.inst, nullptr, nullptr))
				//auto k = img_infos.upper_bound(t.inst);
				//--k;
				//RTN rtn = RTN_FindByAddress(t.inst);
				ptrdiff_t offset = i->second.StartSP - t.mem;
				fprintf(outstream, "%c|%td|%td"/*[%s!%s+%p]*/ "\n",
					"RW"[t.rw],
					offset,
					IMG_Valid(img)?t.inst-IMG_StartAddress(img):t.inst /*IMG_Name(img).c_str(), RTN_Name(rtn).c_str(), (void*)(t.inst - RTN_Address(rtn)),*/ /*buf*/);
			}
			thread_infos.erase(i);
		}
	}, NULL);

	INS_AddInstrumentFunction(
		[](INS ins, VOID *v) -> VOID {
		typedef VOID(*_ana_calls)(INS, IPOINT);
		static const _ana_calls ana_calls[2][2][2] = {
			// W, R, R2
			/* F, F, F*/[](INS ins, IPOINT action) {
				INS_InsertCall(ins, action, (AFUNPTR)ins_ana_nomem, 
					IARG_REG_VALUE, RegTinfo, 
					IARG_INST_PTR,
					IARG_END);},
			/* F, F, T*/NULL,
			/* F, T, F*/[](INS ins, IPOINT action) {
				INS_InsertCall(ins, action, (AFUNPTR)ins_ana_r, 
					IARG_REG_VALUE, RegTinfo,
					IARG_INST_PTR,
					IARG_MEMORYREAD_EA, 
					IARG_MEMORYREAD_SIZE, 
					IARG_END);},
			/* F, T, T*/[](INS ins, IPOINT action) {
				INS_InsertCall(ins, action, (AFUNPTR)ins_ana_rr,
					IARG_REG_VALUE, RegTinfo,
					IARG_INST_PTR,
					IARG_MEMORYREAD_EA, 
					IARG_MEMORYREAD2_EA, 
					IARG_MEMORYREAD_SIZE, 
					IARG_END);},
			/* T, F, F*/[](INS ins, IPOINT action) {
				INS_InsertCall(ins, action, (AFUNPTR)ins_ana_w,
					IARG_REG_VALUE, RegTinfo,
					IARG_INST_PTR,
					IARG_MEMORYWRITE_EA, 
					IARG_MEMORYWRITE_SIZE,
					IARG_END);},
			/* T, F, T*/NULL,
			/* T, T, F*/[](INS ins, IPOINT action) {
				INS_InsertCall(ins, action, (AFUNPTR)ins_ana_rw,
					IARG_REG_VALUE, RegTinfo,
					IARG_INST_PTR,
					IARG_MEMORYREAD_EA, 
					IARG_MEMORYREAD_SIZE, 
					IARG_MEMORYWRITE_EA, 
					IARG_MEMORYWRITE_SIZE,
					IARG_END);},
			/* T, T, T*/[](INS ins, IPOINT action) {
				INS_InsertCall(ins, action, (AFUNPTR)ins_ana_rrw,
					IARG_REG_VALUE, RegTinfo,
					IARG_INST_PTR,
					IARG_MEMORYREAD_EA, 
					IARG_MEMORYREAD2_EA, 
					IARG_MEMORYREAD_SIZE, 
					IARG_MEMORYWRITE_EA, 
					IARG_MEMORYWRITE_SIZE,
					IARG_END);},
		};
		auto* f = ana_calls[INS_IsMemoryWrite(ins)][INS_IsMemoryRead(ins)][INS_HasMemoryRead2(ins)];
		if (f)
			f(ins, IPOINT_BEFORE);
	}, NULL);


	PIN_AddFiniFunction([](INT32 code, VOID *v) -> VOID{
		fclose(outstream);
	}, NULL);

	PIN_StartProgram();
	return 0;
}