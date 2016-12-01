#include <pin.H>
#include <iostream>

VOID esp_record(const CONTEXT *ctxt, THREADID tid) {
	cout << "try to break" << endl << flush;
	PIN_WaitForDebuggerToConnect(0);
	PIN_ApplicationBreakpoint(ctxt, tid, TRUE, "dobreak");
}

static ADDRINT entrypoint;
static bool entry_start = false;
static ADDRINT entry_stack;

static VOID print_esp_on_entry(ADDRINT esp) {
	entry_stack = esp;
	cout << "esp on entry " << hex << esp << dec << endl << flush;
}

static ADDRINT print_esp_change(ADDRINT esp) {
	//cout << "stack = " << entry_stack - esp << endl << flush;
	return entry_stack == esp;
}

static VOID DoBreakpoint(const CONTEXT *ctxt, THREADID tid)
{
	PIN_WaitForDebuggerToConnect(0);
	PIN_ApplicationBreakpoint(ctxt, tid, TRUE, "esp restored");
}

int main(int argc, char** argv) {
	PIN_Init(argc, argv);
	IMG_AddInstrumentFunction([](IMG img, VOID *) {
		if (IMG_IsMainExecutable(img)) {
			cout << "find main exec " << img.index << endl << flush;
			entrypoint = IMG_Entry(img);
			cout << "entrypoint @ " << hex << entrypoint << dec << endl << flush;
			INS_AddInstrumentFunction([](INS ins, VOID*) {
				if (!entry_start && INS_Address(ins) != entrypoint) {
					return;
				}
				if (!entry_start) {
					INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)print_esp_on_entry, IARG_REG_VALUE, REG_STACK_PTR, IARG_END);
					entry_start = true;
				}
				if (INS_RegWContain(ins, REG_STACK_PTR))
				{
					IPOINT where = IPOINT_AFTER;
					if (!INS_HasFallThrough(ins))
					where = IPOINT_TAKEN_BRANCH;

					INS_InsertIfCall(ins, where, (AFUNPTR)print_esp_change, IARG_REG_VALUE, REG_STACK_PTR, IARG_END);
					INS_InsertThenCall(ins, where, (AFUNPTR)DoBreakpoint,
						IARG_CONST_CONTEXT, IARG_THREAD_ID, IARG_END);
				}
			}, NULL);
		}
	}, NULL);
	PIN_StartProgram();
	return 0;
}