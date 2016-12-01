#include <Windows.h>
#include <cstdlib>
#include <cstdio>
#include <malloc.h>

int main(int argc, char** argv) {
	char *pin, *app;
	if (!(pin = getenv("PIN_CMD")) || !(app = getenv("APP_CMD")))
		return -1;

	HANDLE pipe_write, h_pin, h_app;
	PROCESS_INFORMATION proc_pin, proc_app;
	STARTUPINFO info_app{ sizeof(STARTUPINFO) }, info_pin{ sizeof(STARTUPINFO) };
	
	info_app.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	info_app.hStdError = GetStdHandle(STD_ERROR_HANDLE);
	info_app.dwFlags = STARTF_USESTDHANDLES;
	//create pipe
	SECURITY_ATTRIBUTES sattr{sizeof(sattr), NULL, TRUE};
	if (!CreatePipe(&info_app.hStdInput, &pipe_write, &sattr, 0) || 
		!SetHandleInformation(pipe_write, HANDLE_FLAG_INHERIT, 0)) {
		goto api_error;
	}
	//create app process
	if (!CreateProcess(NULL, app, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &info_app, &proc_app) ||
		!CloseHandle(info_app.hStdInput) ||
		!DuplicateHandle(GetCurrentProcess(), pipe_write, proc_app.hProcess, &pipe_write,
			0, FALSE, DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS))
		goto api_error;

	char* app_pipe_pid = (char*)alloca(snprintf(NULL, 0, "%lx", proc_app.dwProcessId) + 1);
	char* app_pipe_handle = (char*)alloca(snprintf(NULL, 0, "%p", pipe_write) + 1);
	sprintf(app_pipe_pid, "%lx", proc_app.dwProcessId);
	sprintf(app_pipe_handle, "%p", pipe_write);
	//create pin process
	if (!SetEnvironmentVariable("APP_PIPE_PID", app_pipe_pid) ||
		!SetEnvironmentVariable("APP_PIPE_HANDLE", app_pipe_handle) ||
		!CreateProcess(NULL, pin, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &info_pin, &proc_pin) ) {
		goto api_error;
	}
	//start
	if (!ResumeThread(proc_app.hThread) || !ResumeThread(proc_pin.hThread)) {
		goto api_error;
	}
	return 0;
api_error:
	return GetLastError();
}