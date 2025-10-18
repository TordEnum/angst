// sandbox_exec.cpp - Minimal C++ sandbox wrapper
// Build: g++ -O2 -std=c++17 sandbox_exec.cpp -o sandbox_exec
// Usage: ./sandbox_exec --time <sec> --mem <bytes> --stdout <cap> -- <cmd> [args...]
// Prints JSON with fields: ok, timeout, status, stdout, stderr

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

#include <string>
#include <vector>
#include <sstream>
#include <iostream>
#include <algorithm>

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

static void set_nonblock(int fd){ int fl = fcntl(fd, F_GETFL, 0); fcntl(fd, F_SETFL, fl | O_NONBLOCK); }

int main(int argc, char** argv){
    int time_sec = 3; long mem_bytes = 256*1024*1024; size_t stdout_cap = 200000;
    int sep = -1;
    for(int i=1;i<argc;i++){
        std::string a(argv[i]);
        if(a == "--time" && i+1<argc){ time_sec = std::stoi(argv[++i]); }
        else if(a == "--mem" && i+1<argc){ mem_bytes = std::stol(argv[++i]); }
        else if(a == "--stdout" && i+1<argc){ stdout_cap = (size_t) std::stoll(argv[++i]); }
        else if(a == "--"){ sep = i+1; break; }
    }
    if(sep < 0 || sep >= argc){
        std::cerr << "{\"ok\":false,\"error\":\"no_command\"}" << std::endl; return 2;
    }
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
        // child
        setsid();
        // rlimits
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
        // redirect stdio
        dup2(out_pipe[1], STDOUT_FILENO);
        dup2(err_pipe[1], STDERR_FILENO);
        close(out_pipe[0]); close(out_pipe[1]);
        close(err_pipe[0]); close(err_pipe[1]);
        // exec
        execvp(cmd[0], cmd.data());
        // if exec fails
        std::string msg = std::string("exec_failed:") + strerror(errno);
        std::cerr << msg << std::endl;
        _exit(127);
    }

    // parent
    close(out_pipe[1]); close(err_pipe[1]);
    set_nonblock(out_pipe[0]); set_nonblock(err_pipe[0]);

    std::string out, err;
    out.reserve(8192); err.reserve(4096);
    int status = 0; bool timeout = false;
    auto deadline = time(nullptr) + time_sec + 1;

    while(true){
        // read pipes
        char buf[4096];
        ssize_t n = read(out_pipe[0], buf, sizeof(buf));
        if(n > 0){ out.append(buf, buf + std::min((size_t)n, stdout_cap - std::min(stdout_cap, out.size()))); }
        n = read(err_pipe[0], buf, sizeof(buf));
        if(n > 0){ err.append(buf, buf + std::min((size_t)n, (size_t)65536 - std::min((size_t)65536, err.size()))); }
        // check child
        pid_t w = waitpid(pid, &status, WNOHANG);
        if(w == pid){ break; }
        if(time(nullptr) > deadline){ timeout = true; break; }
        usleep(1000*2);
    }

    if(timeout){
        // kill process group
        kill(-pid, SIGKILL);
        waitpid(pid, &status, 0);
    }

    bool ok = (!timeout) && WIFEXITED(status) && (WEXITSTATUS(status) == 0);
    std::ostringstream ss;
    ss << "{";
    ss << "\"ok\":" << (ok?"true":"false") << ",";
    ss << "\"timeout\":" << (timeout?"true":"false") << ",";
    ss << "\"status\":" << (WIFEXITED(status)?WEXITSTATUS(status):-1) << ",";
    ss << "\"stdout\":\"" << json_escape(out) << "\",";
    ss << "\"stderr\":\"" << json_escape(err) << "\"";
    ss << "}";
    std::cout << ss.str() << std::endl;
    return ok ? 0 : 1;
}
