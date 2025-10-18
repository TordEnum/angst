// sandbox_exec.cpp - Minimal cross-platform sandbox wrapper
// Linux build: g++ -O2 -std=c++17 sandbox_exec.cpp -o sandbox_exec
// Windows build (MSVC): cl /O2 /std:c++17 sandbox_exec.cpp
// Usage: sandbox_exec --time <sec> --mem <bytes> --stdout <cap> -- <cmd> [args...]
// Output: JSON with fields: ok, timeout, status, stdout, stderr

#include <string>
#include <vector>
#include <sstream>
#include <iostream>
#include <algorithm>

#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #include <windows.h>
  #include <processthreadsapi.h>
  #include <handleapi.h>
  #include <synchapi.h>
  #include <io.h>
#else
  #include <sys/types.h>
  #include <sys/wait.h>
  #include <sys/resource.h>
  #include <sys/time.h>
  #include <time.h>
  #ifdef __linux__
  #include <sys/prctl.h>
  #endif
  #include <signal.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <errno.h>
  #include <string.h>
#endif

static std::string json_escape(const std::string &s){
    std::string o; o.reserve(s.size()+16);
    for(char c: s){
        switch(c){
            case '\\': o += "\\\\"; break;
            case '"': o += "\\\""; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default: o += c; break;
        }
    }
    return o;
}

#ifndef _WIN32
static void set_nonblock(int fd){ int fl = fcntl(fd, F_GETFL, 0); fcntl(fd, F_SETFL, fl | O_NONBLOCK); }
#endif

int main(int argc, char** argv){
    int time_sec = 3; long long mem_bytes = 256ll*1024*1024; size_t stdout_cap = 200000;
    int sep = -1;
    for(int i=1;i<argc;i++){
        std::string a(argv[i]);
        if(a == "--time" && i+1<argc){ time_sec = std::stoi(argv[++i]); }
        else if(a == "--mem" && i+1<argc){ mem_bytes = std::stoll(argv[++i]); }
        else if(a == "--stdout" && i+1<argc){ stdout_cap = (size_t) std::stoll(argv[++i]); }
        else if(a == "--"){ sep = i+1; break; }
    }
    if(sep < 0 || sep >= argc){
        std::cerr << "{\"ok\":false,\"error\":\"no_command\"}" << std::endl; return 2;
    }

#ifdef _WIN32
    // Windows implementation
    SECURITY_ATTRIBUTES sa; ZeroMemory(&sa, sizeof(sa)); sa.nLength = sizeof(sa); sa.bInheritHandle = TRUE;
    HANDLE outRead=NULL, outWrite=NULL, errRead=NULL, errWrite=NULL;
    if(!CreatePipe(&outRead, &outWrite, &sa, 0) || !CreatePipe(&errRead, &errWrite, &sa, 0)){
        std::cerr << "{\"ok\":false,\"error\":\"pipe\"}" << std::endl; return 3;
    }
    SetHandleInformation(outRead, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(errRead, HANDLE_FLAG_INHERIT, 0);

    auto needs_quote = [](const std::string& s){ return s.find_first_of(" \t\"\\") != std::string::npos; };
    auto quote = [&](const std::string& s){
        if(!needs_quote(s)) return s;
        std::string r = "\""; r.reserve(s.size()+2);
        int bs = 0;
        for(char c: s){
            if(c == '\\') { bs++; r.push_back('\\'); }
            else if(c == '"') { r.append(std::string(bs,'\\')); r.push_back('\\'); r.push_back('"'); bs = 0; }
            else { bs = 0; r.push_back(c); }
        }
        r.append(std::string(bs,'\\')); r.push_back('"');
        return r;
    };
    std::string cmdline;
    for(int i=sep;i<argc;i++){
        if(i>sep) cmdline.push_back(' ');
        cmdline += quote(argv[i]);
    }

    auto widen = [](const std::string& s){
        int wlen = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, NULL, 0);
        if(wlen <= 0){ std::wstring w; w.push_back(L'\0'); return w; }
        std::wstring w; w.resize((size_t)wlen);
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], wlen);
        return w;
    };
    std::wstring wcmd = widen(cmdline);

    STARTUPINFOW si; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = outWrite;
    si.hStdError  = errWrite;
    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));

    if(!CreateProcessW(NULL, &wcmd[0], NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)){
        std::cerr << "{\"ok\":false,\"error\":\"create_process\"}" << std::endl; return 4;
    }

    CloseHandle(outWrite); CloseHandle(errWrite);

    // Create job object: kill on job close and optional per-process memory limit
    HANDLE hJob = CreateJobObjectW(NULL, NULL);
    if(hJob){
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info; ZeroMemory(&info, sizeof(info));
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if(mem_bytes > 0){
            info.ProcessMemoryLimit = (SIZE_T)mem_bytes;
            info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        }
        SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &info, sizeof(info));
        AssignProcessToJobObject(hJob, pi.hProcess);
    }

    std::string out; out.reserve(8192);
    std::string err; err.reserve(4096);
    const ULONGLONG deadline = GetTickCount64() + (ULONGLONG)(time_sec + 1) * 1000ULL;
    bool timeout = false;

    auto drain = [&](HANDLE h, std::string& dst, size_t cap){
        char buf[4096]; DWORD avail=0, read=0;
        while(dst.size() < cap){
            if(!PeekNamedPipe(h, NULL, 0, NULL, &avail, NULL)) break;
            if(avail == 0) break;
            DWORD to_read = (DWORD)std::min<size_t>(sizeof(buf), std::min<size_t>(avail, cap - dst.size()));
            if(!ReadFile(h, buf, to_read, &read, NULL) || read == 0) break;
            dst.append(buf, buf + read);
        }
    };

    for(;;){
        drain(outRead, out, stdout_cap);
        drain(errRead, err, 65536);
        DWORD wait = WaitForSingleObject(pi.hProcess, 10);
        if(wait == WAIT_OBJECT_0) break;
        if(GetTickCount64() > deadline){ timeout = true; break; }
    }
    if(timeout){
        if(hJob) TerminateJobObject(hJob, 1);
        else TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 1000);
    }
    // Final drain
    drain(outRead, out, stdout_cap);
    drain(errRead, err, 65536);

    DWORD code=0; GetExitCodeProcess(pi.hProcess, &code);
    bool ok = (!timeout) && code == 0;
    std::ostringstream ss; ss << "{";
    ss << "\"ok\":" << (ok?"true":"false") << ",";
    ss << "\"timeout\":" << (timeout?"true":"false") << ",";
    ss << "\"status\":" << (timeout?-1:(int)code) << ",";
    ss << "\"stdout\":\"" << json_escape(out) << "\",";
    ss << "\"stderr\":\"" << json_escape(err) << "\"";
    ss << "}";
    std::cout << ss.str() << std::endl;
    if(hJob) CloseHandle(hJob);
    CloseHandle(outRead); CloseHandle(errRead);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return ok ? 0 : 1;

#else
    // POSIX implementation (Linux/macOS)
    std::vector<char*> cmd;
    for(int i=sep; i<argc; i++) cmd.push_back(argv[i]);
    cmd.push_back(nullptr);

    int out_pipe[2]; int err_pipe[2];
    if(pipe(out_pipe) || pipe(err_pipe)){
        std::cerr << "{\"ok\":false,\"error\":\"pipe\"}" << std::endl; return 3;
    }

    pid_t pid = fork();
    if(pid < 0){
        std::cerr << "{\"ok\":false,\"error\":\"fork\"}" << std::endl; return 4;
    }
    if(pid == 0){
        setsid();
        struct rlimit rl;
        rl.rlim_cur = rl.rlim_max = (rlim_t) time_sec; setrlimit(RLIMIT_CPU, &rl);
        rl.rlim_cur = rl.rlim_max = (rlim_t) mem_bytes; setrlimit(RLIMIT_AS, &rl);
        rl.rlim_cur = rl.rlim_max = (rlim_t) 1024*1024; setrlimit(RLIMIT_FSIZE, &rl);
        rl.rlim_cur = rl.rlim_max = (rlim_t) 256; setrlimit(RLIMIT_NOFILE, &rl);
        #ifdef __linux__
        #ifdef PR_SET_NO_NEW_PRIVS
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        #endif
        #endif
        dup2(out_pipe[1], STDOUT_FILENO);
        dup2(err_pipe[1], STDERR_FILENO);
        close(out_pipe[0]); close(out_pipe[1]);
        close(err_pipe[0]); close(err_pipe[1]);
        execvp(cmd[0], cmd.data());
        std::string msg = std::string("exec_failed:") + strerror(errno);
        std::cerr << msg << std::endl;
        _exit(127);
    }
    close(out_pipe[1]); close(err_pipe[1]);
    set_nonblock(out_pipe[0]); set_nonblock(err_pipe[0]);
    std::string out, err; out.reserve(8192); err.reserve(4096);
    int status = 0; bool timeout = false;
    auto deadline = time(nullptr) + time_sec + 1;
    while(true){
        char buf[4096];
        ssize_t n = read(out_pipe[0], buf, sizeof(buf));
        if(n > 0){ out.append(buf, buf + std::min((size_t)n, stdout_cap - std::min(stdout_cap, out.size())); }
        n = read(err_pipe[0], buf, sizeof(buf));
        if(n > 0){ err.append(buf, buf + std::min((size_t)n, (size_t)65536 - std::min((size_t)65536, err.size())); }
        pid_t w = waitpid(pid, &status, WNOHANG);
        if(w == pid){ break; }
        if(time(nullptr) > deadline){ timeout = true; break; }
        usleep(1000*2);
    }
    if(timeout){ kill(-pid, SIGKILL); waitpid(pid, &status, 0); }
    bool ok = (!timeout) && WIFEXITED(status) && (WEXITSTATUS(status) == 0);
    std::ostringstream ss; ss << "{";
    ss << "\"ok\":" << (ok?"true":"false") << ",";
    ss << "\"timeout\":" << (timeout?"true":"false") << ",";
    ss << "\"status\":" << (WIFEXITED(status)?WEXITSTATUS(status):-1) << ",";
    ss << "\"stdout\":\"" << json_escape(out) << "\",";
    ss << "\"stderr\":\"" << json_escape(err) << "\"";
    ss << "}";
    std::cout << ss.str() << std::endl;
    return ok ? 0 : 1;
#endif
}
