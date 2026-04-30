
#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <ctime>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace std;

static volatile sig_atomic_t g_stop = 0;

static const int DEFAULT_SCAN_INTERVAL = 20;
static const int DEFAULT_PROCESS_INTERVAL = 30;
static const int DEFAULT_SESSION_GAP_MINUTES = 15;
static const long long DEFAULT_MAX_FILE_SIZE = 50000000LL;

struct Paths {
    string home;
    string config_dir;
    string data_dir;
    string state_dir;
    string config_path;
    string events_path;
    string state_path;
    string pid_path;
};

struct Config {
    vector<string> watch_dirs;
    int scan_interval_seconds = DEFAULT_SCAN_INTERVAL;
    int process_interval_seconds = DEFAULT_PROCESS_INTERVAL;
    int session_gap_minutes = DEFAULT_SESSION_GAP_MINUTES;
    long long max_file_size_bytes = DEFAULT_MAX_FILE_SIZE;
};

struct FileMeta {
    long long mtime_ns = 0;
    long long size = 0;
    string dir;
    string file;
};

struct Event {
    time_t ts = 0;
    string iso;
    string type;
    string directory;
    string process;
    string target;
    string cmdline;
};

struct Session {
    time_t start = 0;
    time_t end = 0;
    int events = 0;
};

struct DirStats {
    string path;
    int events = 0;
    int sessions = 0;
    long long estimated_minutes = 0;
    time_t last_active = 0;
    map<string, int> top_files;
    vector<Session> session_list;
};

static set<string> ignored_dir_names = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache",
    "target", "build", "dist", ".cache", ".cargo", ".rustup"
};

static set<string> watched_process_names = {
    "vim", "nvim", "nano", "touch", "bash", "zsh", "fish", "sh", "python", "python3", "make", "gcc", "clang", "git"
};

static string getenv_or_empty(const char* key) {
    const char* v = getenv(key);
    return v ? string(v) : string();
}

static Paths paths() {
    Paths p;
    p.home = getenv_or_empty("HOME");
    if (p.home.empty()) p.home = ".";
    p.config_dir = p.home + "/.config/gravity";
    p.data_dir = p.home + "/.local/share/gravity";
    p.state_dir = p.home + "/.local/state/gravity";
    p.config_path = p.config_dir + "/config.txt";
    p.events_path = p.data_dir + "/events.jsonl";
    p.state_path = p.data_dir + "/state.tsv";
    p.pid_path = p.data_dir + "/gravityd.pid";
    return p;
}

static bool mkdir_p(const string& path) {
    if (path.empty()) return false;
    string cur;
    if (path[0] == '/') cur = "/";
    stringstream ss(path);
    string part;
    while (getline(ss, part, '/')) {
        if (part.empty()) continue;
        if (cur.size() > 1) cur += "/";
        cur += part;
        if (mkdir(cur.c_str(), 0755) != 0 && errno != EEXIST) return false;
    }
    return true;
}

static void ensure_dirs() {
    Paths p = paths();
    mkdir_p(p.config_dir);
    mkdir_p(p.data_dir);
    mkdir_p(p.state_dir);
}

static string trim(const string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

static string shell_expand_home(const string& raw) {
    Paths p = paths();
    if (raw == "~") return p.home;
    if (raw.rfind("~/", 0) == 0) return p.home + raw.substr(1);
    return raw;
}

static string realpath_or_self(const string& in) {
    string expanded = shell_expand_home(in);
    char buf[PATH_MAX];
    if (realpath(expanded.c_str(), buf)) return string(buf);
    return expanded;
}

static string dirname_of(const string& path) {
    size_t pos = path.find_last_of('/');
    if (pos == string::npos) return ".";
    if (pos == 0) return "/";
    return path.substr(0, pos);
}

static string basename_of(const string& path) {
    size_t pos = path.find_last_of('/');
    if (pos == string::npos) return path;
    return path.substr(pos + 1);
}

static string shorten_path(const string& path) {
    Paths p = paths();
    string h = p.home;
    if (path == h) return "~";
    if (path.rfind(h + "/", 0) == 0) return "~" + path.substr(h.size());
    return path;
}

static string file_url(const string& path) {
    return "file://" + realpath_or_self(path);
}

static string escape_json(const string& s) {
    string out;
    for (char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if ((unsigned char)c < 32) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

static string html_escape(const string& s) {
    string out;
    for (char c : s) {
        if (c == '&') out += "&amp;";
        else if (c == '<') out += "&lt;";
        else if (c == '>') out += "&gt;";
        else if (c == '"') out += "&quot;";
        else out += c;
    }
    return out;
}

static time_t now_time() {
    return time(nullptr);
}

static string iso_local(time_t t) {
    char buf[64];
    tm lt{};
    localtime_r(&t, &lt);
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S%z", &lt);
    return string(buf);
}

static string human_day(time_t t) {
    char buf[64];
    tm lt{};
    localtime_r(&t, &lt);
    strftime(buf, sizeof(buf), "%b %d", &lt);
    return string(buf);
}

static string human_datetime(time_t t) {
    char buf[64];
    tm lt{};
    localtime_r(&t, &lt);
    strftime(buf, sizeof(buf), "%Y-%m-%d %I:%M %p", &lt);
    return string(buf);
}

static bool parse_iso_rough(const string& iso, time_t& out) {
    // Reads the local YYYY-MM-DDTHH:MM:SS prefix. Good enough for local monthly reports.
    if (iso.size() < 19) return false;
    tm tmv{};
    string prefix = iso.substr(0, 19);
    istringstream ss(prefix);
    ss >> get_time(&tmv, "%Y-%m-%dT%H:%M:%S");
    if (ss.fail()) return false;
    tmv.tm_isdst = -1;
    out = mktime(&tmv);
    return out != (time_t)-1;
}

static string current_month() {
    time_t t = now_time();
    tm lt{};
    localtime_r(&t, &lt);
    char buf[16];
    strftime(buf, sizeof(buf), "%Y-%m", &lt);
    return string(buf);
}

static string month_label(const string& month) {
    tm tmv{};
    tmv.tm_year = stoi(month.substr(0, 4)) - 1900;
    tmv.tm_mon = stoi(month.substr(5, 2)) - 1;
    tmv.tm_mday = 1;
    char buf[64];
    strftime(buf, sizeof(buf), "%B %Y", &tmv);
    return string(buf);
}

static pair<time_t, time_t> month_bounds(const string& month) {
    tm start{};
    int y = stoi(month.substr(0, 4));
    int m = stoi(month.substr(5, 2));
    start.tm_year = y - 1900;
    start.tm_mon = m - 1;
    start.tm_mday = 1;
    start.tm_isdst = -1;
    time_t a = mktime(&start);
    tm end = start;
    end.tm_mon += 1;
    time_t b = mktime(&end);
    return {a, b};
}

static string format_minutes(long long mins) {
    long long h = mins / 60;
    long long m = mins % 60;
    stringstream ss;
    if (h > 0) ss << h << "h " << setw(2) << setfill('0') << m << "m";
    else ss << m << "m";
    return ss.str();
}

static Config load_config() {
    ensure_dirs();
    Config cfg;
    Paths p = paths();
    ifstream f(p.config_path);
    string line;
    while (getline(f, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        size_t eq = line.find('=');
        if (eq == string::npos) continue;
        string key = trim(line.substr(0, eq));
        string val = trim(line.substr(eq + 1));
        if (key == "watch") cfg.watch_dirs.push_back(realpath_or_self(val));
        else if (key == "scan_interval_seconds") cfg.scan_interval_seconds = max(1, stoi(val));
        else if (key == "process_interval_seconds") cfg.process_interval_seconds = max(1, stoi(val));
        else if (key == "session_gap_minutes") cfg.session_gap_minutes = max(1, stoi(val));
        else if (key == "max_file_size_bytes") cfg.max_file_size_bytes = stoll(val);
    }
    return cfg;
}

static void save_config(const Config& cfg) {
    ensure_dirs();
    Paths p = paths();
    ofstream f(p.config_path, ios::trunc);
    f << "# Gravity config\n";
    f << "scan_interval_seconds=" << cfg.scan_interval_seconds << "\n";
    f << "process_interval_seconds=" << cfg.process_interval_seconds << "\n";
    f << "session_gap_minutes=" << cfg.session_gap_minutes << "\n";
    f << "max_file_size_bytes=" << cfg.max_file_size_bytes << "\n";
    for (const string& w : cfg.watch_dirs) f << "watch=" << w << "\n";
}

static void append_event(const string& type, const string& directory, const string& process, const string& target, const string& cmdline = "") {
    ensure_dirs();
    Paths p = paths();
    ofstream f(p.events_path, ios::app);
    time_t t = now_time();
    f << "{"
      << "\"ts\":\"" << escape_json(iso_local(t)) << "\"," 
      << "\"type\":\"" << escape_json(type) << "\"," 
      << "\"directory\":\"" << escape_json(directory) << "\"," 
      << "\"process\":\"" << escape_json(process) << "\"," 
      << "\"target\":\"" << escape_json(target) << "\"";
    if (!cmdline.empty()) f << ",\"cmdline\":\"" << escape_json(cmdline) << "\"";
    f << "}\n";
}

static bool starts_with_path(const string& path, const string& root) {
    if (path == root) return true;
    return path.rfind(root + "/", 0) == 0;
}

static bool is_ignored_path(const string& path) {
    stringstream ss(path);
    string part;
    while (getline(ss, part, '/')) {
        if (ignored_dir_names.count(part)) return true;
    }
    return false;
}

static bool stat_file(const string& path, FileMeta& meta) {
    struct stat st{};
    if (stat(path.c_str(), &st) != 0) return false;
    if (!S_ISREG(st.st_mode)) return false;
#if defined(__linux__)
    meta.mtime_ns = (long long)st.st_mtim.tv_sec * 1000000000LL + st.st_mtim.tv_nsec;
#else
    meta.mtime_ns = (long long)st.st_mtime * 1000000000LL;
#endif
    meta.size = st.st_size;
    meta.dir = dirname_of(path);
    meta.file = basename_of(path);
    return true;
}

static void scan_dir_recursive(const string& root, Config& cfg, unordered_map<string, FileMeta>& out) {
    DIR* d = opendir(root.c_str());
    if (!d) return;
    dirent* ent;
    while ((ent = readdir(d)) != nullptr) {
        string name = ent->d_name;
        if (name == "." || name == "..") continue;
        if (ignored_dir_names.count(name)) continue;
        string path = root + "/" + name;
        struct stat st{};
        if (lstat(path.c_str(), &st) != 0) continue;
        if (S_ISLNK(st.st_mode)) continue;
        if (S_ISDIR(st.st_mode)) {
            if (!is_ignored_path(path)) scan_dir_recursive(path, cfg, out);
        } else if (S_ISREG(st.st_mode)) {
            if (st.st_size > cfg.max_file_size_bytes) continue;
            FileMeta fm;
            if (stat_file(path, fm)) out[path] = fm;
        }
    }
    closedir(d);
}

static unordered_map<string, FileMeta> load_state() {
    unordered_map<string, FileMeta> s;
    Paths p = paths();
    ifstream f(p.state_path);
    string line;
    while (getline(f, line)) {
        vector<string> parts;
        string part;
        stringstream ss(line);
        while (getline(ss, part, '\t')) parts.push_back(part);
        if (parts.size() < 4) continue;
        FileMeta fm;
        fm.mtime_ns = atoll(parts[1].c_str());
        fm.size = atoll(parts[2].c_str());
        fm.dir = dirname_of(parts[0]);
        fm.file = basename_of(parts[0]);
        s[parts[0]] = fm;
    }
    return s;
}

static void save_state(const unordered_map<string, FileMeta>& s) {
    ensure_dirs();
    Paths p = paths();
    string tmp = p.state_path + ".tmp";
    ofstream f(tmp, ios::trunc);
    for (const auto& kv : s) {
        f << kv.first << '\t' << kv.second.mtime_ns << '\t' << kv.second.size << '\t' << kv.second.dir << '\n';
    }
    f.close();
    rename(tmp.c_str(), p.state_path.c_str());
}

static string read_file_string(const string& path) {
    ifstream f(path, ios::binary);
    if (!f) return "";
    stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static string readlink_string(const string& path) {
    char buf[PATH_MAX + 1];
    ssize_t n = readlink(path.c_str(), buf, PATH_MAX);
    if (n < 0) return "";
    buf[n] = '\0';
    return string(buf);
}

static string event_type_for_process(const string& name) {
    if (name == "vim" || name == "nvim" || name == "nano") return "editor_active";
    if (name == "bash" || name == "zsh" || name == "fish" || name == "sh") return "session_active";
    if (name == "touch") return "touch_active";
    return "process_active";
}

static void sample_processes(const Config& cfg) {
    DIR* proc = opendir("/proc");
    if (!proc) return;
    dirent* ent;
    while ((ent = readdir(proc)) != nullptr) {
        string pid = ent->d_name;
        if (!all_of(pid.begin(), pid.end(), ::isdigit)) continue;
        string base = "/proc/" + pid;
        string comm = trim(read_file_string(base + "/comm"));
        if (!watched_process_names.count(comm)) continue;
        string cwd = readlink_string(base + "/cwd");
        if (cwd.empty()) continue;
        bool inside = false;
        for (const string& root : cfg.watch_dirs) {
            if (starts_with_path(cwd, root)) {
                inside = true;
                break;
            }
        }
        if (!inside) continue;
        string cmdline = read_file_string(base + "/cmdline");
        for (char& c : cmdline) if (c == '\0') c = ' ';
        cmdline = trim(cmdline);
        string tty = readlink_string(base + "/fd/0");
        string target = tty.empty() ? ("pid:" + pid) : tty;
        append_event(event_type_for_process(comm), cwd, comm, target, cmdline);
    }
    closedir(proc);
}

static void scan_files_once(Config& cfg, unordered_map<string, FileMeta>& state) {
    for (const string& root : cfg.watch_dirs) {
        unordered_map<string, FileMeta> current;
        scan_dir_recursive(root, cfg, current);
        for (const auto& kv : current) {
            const string& path = kv.first;
            const FileMeta& fm = kv.second;
            auto it = state.find(path);
            if (it == state.end()) {
                append_event("file_create", fm.dir, "watcher", path);
            } else if (it->second.mtime_ns != fm.mtime_ns || it->second.size != fm.size) {
                append_event("file_modify", fm.dir, "watcher", path);
            }
            state[path] = fm;
        }
    }
}

static void on_signal(int) {
    g_stop = 1;
}

static int cmd_daemon() {
    ensure_dirs();
    Paths p = paths();
    {
        ofstream pid(p.pid_path, ios::trunc);
        pid << getpid() << "\n";
    }
    signal(SIGTERM, on_signal);
    signal(SIGINT, on_signal);
    append_event("daemon_start", paths().home, "gravityd", "gravityd");

    unordered_map<string, FileMeta> state = load_state();
    time_t last_process_sample = 0;

    while (!g_stop) {
        Config cfg = load_config();
        scan_files_once(cfg, state);
        time_t n = now_time();
        if (n - last_process_sample >= cfg.process_interval_seconds) {
            sample_processes(cfg);
            last_process_sample = n;
        }
        save_state(state);
        this_thread::sleep_for(chrono::seconds(max(1, cfg.scan_interval_seconds)));
    }

    append_event("daemon_stop", paths().home, "gravityd", "gravityd");
    unlink(p.pid_path.c_str());
    return 0;
}

static bool json_get_string(const string& line, const string& key, string& out) {
    string pat = "\"" + key + "\":\"";
    size_t pos = line.find(pat);
    if (pos == string::npos) return false;
    pos += pat.size();
    string val;
    bool esc = false;
    for (size_t i = pos; i < line.size(); ++i) {
        char c = line[i];
        if (esc) {
            if (c == 'n') val += '\n';
            else if (c == 't') val += '\t';
            else val += c;
            esc = false;
        } else if (c == '\\') {
            esc = true;
        } else if (c == '"') {
            out = val;
            return true;
        } else val += c;
    }
    return false;
}

static vector<Event> load_month_events(const string& month) {
    Paths p = paths();
    pair<time_t, time_t> bounds = month_bounds(month);
    vector<Event> out;
    ifstream f(p.events_path);
    string line;
    while (getline(f, line)) {
        Event e;
        if (!json_get_string(line, "ts", e.iso)) continue;
        if (!parse_iso_rough(e.iso, e.ts)) continue;
        if (e.ts < bounds.first || e.ts >= bounds.second) continue;
        json_get_string(line, "type", e.type);
        json_get_string(line, "directory", e.directory);
        json_get_string(line, "process", e.process);
        json_get_string(line, "target", e.target);
        json_get_string(line, "cmdline", e.cmdline);
        out.push_back(e);
    }
    sort(out.begin(), out.end(), [](const Event& a, const Event& b){ return a.ts < b.ts; });
    return out;
}

static vector<Session> build_sessions_for_dir(vector<time_t> times, int gap_minutes) {
    vector<Session> sessions;
    if (times.empty()) return sessions;
    sort(times.begin(), times.end());
    long long gap = gap_minutes * 60LL;
    Session cur;
    cur.start = times[0];
    cur.end = times[0];
    cur.events = 1;
    for (size_t i = 1; i < times.size(); ++i) {
        if ((long long)(times[i] - cur.end) <= gap) {
            cur.end = times[i];
            cur.events++;
        } else {
            sessions.push_back(cur);
            cur.start = cur.end = times[i];
            cur.events = 1;
        }
    }
    sessions.push_back(cur);
    return sessions;
}

static long long estimate_minutes(const vector<Session>& sessions) {
    long long total = 0;
    for (const auto& s : sessions) {
        long long span = max(0LL, (long long)(s.end - s.start) / 60LL);
        if (s.events <= 1) total += 5;
        else total += max(5LL, span);
    }
    return total;
}

static vector<DirStats> build_report(const string& month) {
    Config cfg = load_config();
    vector<Event> events = load_month_events(month);
    map<string, vector<time_t>> by_dir_times;
    map<string, DirStats> stats;

    for (const Event& e : events) {
        if (e.directory.empty()) continue;
        if (e.type == "daemon_start" || e.type == "daemon_stop") continue;
        DirStats& ds = stats[e.directory];
        ds.path = e.directory;
        ds.events++;
        ds.last_active = max(ds.last_active, e.ts);
        by_dir_times[e.directory].push_back(e.ts);
        if (!e.target.empty() && e.target.rfind("/", 0) == 0) ds.top_files[e.target]++;
    }

    vector<DirStats> dirs;
    for (auto& kv : stats) {
        DirStats ds = kv.second;
        ds.session_list = build_sessions_for_dir(by_dir_times[kv.first], cfg.session_gap_minutes);
        ds.sessions = (int)ds.session_list.size();
        ds.estimated_minutes = estimate_minutes(ds.session_list);
        dirs.push_back(ds);
    }

    sort(dirs.begin(), dirs.end(), [](const DirStats& a, const DirStats& b){
        if (a.estimated_minutes != b.estimated_minutes) return a.estimated_minutes > b.estimated_minutes;
        return a.events > b.events;
    });
    return dirs;
}

static void print_month(const string& month) {
    vector<DirStats> dirs = build_report(month);
    cout << month_label(month) << " — Directory Gravity\n\n";
    if (dirs.empty()) {
        cout << "No activity found for this month.\n";
        return;
    }
    cout << left << setw(44) << "Directory" << right << setw(12) << "Time" << setw(10) << "Events" << setw(10) << "Sessions" << setw(14) << "Last Active" << "\n";
    cout << string(90, '-') << "\n";
    for (const auto& d : dirs) {
        string label = shorten_path(d.path);
        if (label.size() > 43) label = label.substr(0, 40) + "...";
        cout << left << setw(44) << label
             << right << setw(12) << format_minutes(d.estimated_minutes)
             << setw(10) << d.events
             << setw(10) << d.sessions
             << setw(14) << human_day(d.last_active) << "\n";
        cout << "  " << file_url(d.path) << "\n";
    }
}

static void write_json_report(const string& month, const string& out_path) {
    vector<DirStats> dirs = build_report(month);
    ofstream f(out_path, ios::trunc);
    f << "{\n";
    f << "  \"month\": \"" << escape_json(month) << "\",\n";
    f << "  \"directories\": [\n";
    for (size_t i = 0; i < dirs.size(); ++i) {
        const auto& d = dirs[i];
        f << "    {\n";
        f << "      \"path\": \"" << escape_json(d.path) << "\",\n";
        f << "      \"label\": \"" << escape_json(shorten_path(d.path)) << "\",\n";
        f << "      \"events\": " << d.events << ",\n";
        f << "      \"estimated_minutes\": " << d.estimated_minutes << ",\n";
        f << "      \"sessions\": " << d.sessions << ",\n";
        f << "      \"last_active\": \"" << escape_json(iso_local(d.last_active)) << "\",\n";
        f << "      \"file_url\": \"" << escape_json(file_url(d.path)) << "\"\n";
        f << "    }" << (i + 1 == dirs.size() ? "" : ",") << "\n";
    }
    f << "  ]\n";
    f << "}\n";
}

static void write_html_report(const string& month, const string& out_path) {
    vector<DirStats> dirs = build_report(month);
    ofstream f(out_path, ios::trunc);
    f << "<!doctype html><html><head><meta charset='utf-8'>\n";
    f << "<title>Gravity Report " << html_escape(month) << "</title>\n";
    f << "<script src='https://cdn.jsdelivr.net/npm/chart.js'></script>\n";
    f << "<style>body{font-family:system-ui,sans-serif;margin:32px;background:#111;color:#eee}a{color:#8ab4ff}.card{background:#1b1b1b;border:1px solid #333;border-radius:16px;padding:20px;margin:20px 0}table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #333;padding:10px;text-align:left;vertical-align:top}th{color:#bbb}.small{color:#aaa}</style>\n";
    f << "</head><body>\n";
    f << "<h1>" << html_escape(month_label(month)) << " — Directory Gravity</h1>\n";
    f << "<p class='small'>Generated " << html_escape(iso_local(now_time())) << "</p>\n";
    f << "<div class='card'><canvas id='gravityChart' height='110'></canvas></div>\n";
    f << "<div class='card'><h2>Directory Table</h2><table><thead><tr><th>Directory</th><th>Time</th><th>Events</th><th>Sessions</th><th>Last Active</th><th>Top Files</th></tr></thead><tbody>\n";
    for (const auto& d : dirs) {
        f << "<tr><td><a href='" << html_escape(file_url(d.path)) << "'>" << html_escape(shorten_path(d.path)) << "</a></td>";
        f << "<td>" << html_escape(format_minutes(d.estimated_minutes)) << "</td>";
        f << "<td>" << d.events << "</td><td>" << d.sessions << "</td><td>" << html_escape(human_day(d.last_active)) << "</td><td>";
        vector<pair<string,int>> files(d.top_files.begin(), d.top_files.end());
        sort(files.begin(), files.end(), [](auto& a, auto& b){ return a.second > b.second; });
        int count = 0;
        for (const auto& kv : files) {
            if (count++ >= 5) break;
            f << "<a href='" << html_escape(file_url(kv.first)) << "'>" << html_escape(shorten_path(kv.first)) << "</a> <span>" << kv.second << "</span><br>";
        }
        f << "</td></tr>\n";
    }
    f << "</tbody></table></div>\n";
    f << "<script>const labels=[";
    for (size_t i = 0; i < dirs.size() && i < 20; ++i) {
        if (i) f << ",";
        f << "\"" << escape_json(shorten_path(dirs[i].path)) << "\"";
    }
    f << "];const minutes=[";
    for (size_t i = 0; i < dirs.size() && i < 20; ++i) {
        if (i) f << ",";
        f << dirs[i].estimated_minutes;
    }
    f << "];new Chart(document.getElementById('gravityChart'),{type:'bar',data:{labels:labels,datasets:[{label:'Estimated minutes',data:minutes}]},options:{responsive:true}});</script>\n";
    f << "</body></html>\n";
}

static int cmd_watch(vector<string> args) {
    if (args.empty()) {
        cerr << "usage: gravity watch PATH...\n";
        return 2;
    }
    Config cfg = load_config();
    set<string> existing(cfg.watch_dirs.begin(), cfg.watch_dirs.end());
    for (const string& a : args) {
        string p = realpath_or_self(a);
        if (!existing.count(p)) {
            cfg.watch_dirs.push_back(p);
            existing.insert(p);
            cout << "watching " << shorten_path(p) << "\n";
        }
    }
    save_config(cfg);
    return 0;
}

static int cmd_unwatch(vector<string> args) {
    if (args.empty()) {
        cerr << "usage: gravity unwatch PATH...\n";
        return 2;
    }
    Config cfg = load_config();
    set<string> remove;
    for (const string& a : args) remove.insert(realpath_or_self(a));
    vector<string> kept;
    for (const string& w : cfg.watch_dirs) if (!remove.count(w)) kept.push_back(w);
    cfg.watch_dirs = kept;
    save_config(cfg);
    cout << "updated watch list\n";
    return 0;
}

static int cmd_status() {
    Config cfg = load_config();
    Paths p = paths();
    cout << "Gravity status\n";
    cout << "config: " << p.config_path << "\n";
    cout << "events: " << p.events_path << "\n";
    cout << "state:  " << p.state_path << "\n";
    ifstream pid(p.pid_path);
    string pid_s;
    if (getline(pid, pid_s)) cout << "daemon: possibly running pid " << pid_s << "\n";
    else cout << "daemon: no pid file found\n";
    cout << "watch dirs:\n";
    for (const string& w : cfg.watch_dirs) cout << "  " << shorten_path(w) << "\n";
    return 0;
}

static string self_exe_path() {
    string p = readlink_string("/proc/self/exe");
    return p.empty() ? "gravity" : p;
}

static int cmd_install_service() {
    ensure_dirs();
    Paths p = paths();
    string systemd_dir = p.home + "/.config/systemd/user";
    mkdir_p(systemd_dir);
    string service_path = systemd_dir + "/gravityd.service";
    ofstream f(service_path, ios::trunc);
    f << "[Unit]\n";
    f << "Description=Gravity directory activity tracker\n";
    f << "After=default.target\n\n";
    f << "[Service]\n";
    f << "Type=simple\n";
    f << "ExecStart=" << self_exe_path() << " daemon\n";
    f << "Restart=on-failure\n";
    f << "RestartSec=5\n\n";
    f << "[Install]\n";
    f << "WantedBy=default.target\n";
    f.close();
    system("systemctl --user daemon-reload");
    cout << "installed " << service_path << "\n";
    cout << "enable with: systemctl --user enable --now gravityd\n";
    return 0;
}

static int cmd_uninstall_service() {
    system("systemctl --user disable --now gravityd");
    string service_path = paths().home + "/.config/systemd/user/gravityd.service";
    unlink(service_path.c_str());
    system("systemctl --user daemon-reload");
    cout << "removed gravityd user service\n";
    return 0;
}

static int cmd_month(vector<string> args) {
    string month = current_month();
    string json_out;
    bool html = false;
    string html_out;

    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--json") {
            if (i + 1 >= args.size()) {
                cerr << "--json requires output path\n";
                return 2;
            }
            json_out = args[++i];
        } else if (args[i] == "--html") {
            html = true;
        } else if (args[i] == "--html-out") {
            if (i + 1 >= args.size()) {
                cerr << "--html-out requires output path\n";
                return 2;
            }
            html_out = args[++i];
        } else if (args[i].size() == 7 && args[i][4] == '-') {
            month = args[i];
        }
    }

    if (!json_out.empty()) {
        write_json_report(month, json_out);
        cout << "wrote " << json_out << "\n";
    }
    if (html) {
        string out = html_out.empty() ? ("gravity-report-" + month + ".html") : html_out;
        write_html_report(month, out);
        cout << "wrote " << out << "\n";
    }
    if (json_out.empty() && !html) print_month(month);
    return 0;
}

static int cmd_top(vector<string> args) {
    string month = args.empty() ? current_month() : args[0];
    vector<DirStats> dirs = build_report(month);
    int limit = 15;
    for (int i = 0; i < (int)dirs.size() && i < limit; ++i) {
        cout << setw(8) << format_minutes(dirs[i].estimated_minutes)
             << "  " << setw(6) << dirs[i].events << " events  "
             << shorten_path(dirs[i].path) << "\n";
    }
    return 0;
}

static int cmd_sessions(vector<string> args) {
    string month = args.empty() ? current_month() : args[0];
    vector<DirStats> dirs = build_report(month);
    for (const auto& d : dirs) {
        cout << shorten_path(d.path) << "\n";
        int shown = 0;
        for (auto it = d.session_list.rbegin(); it != d.session_list.rend() && shown < 10; ++it, ++shown) {
            long long span = max(0LL, (long long)(it->end - it->start) / 60LL);
            cout << "  " << human_datetime(it->start) << " -> " << human_datetime(it->end)
                 << "  span " << format_minutes(span) << "  events " << it->events << "\n";
        }
    }
    return 0;
}

static int cmd_timeline(vector<string> args) {
    string month = args.empty() ? current_month() : args[0];
    vector<Event> events = load_month_events(month);
    int start = max(0, (int)events.size() - 80);
    for (int i = start; i < (int)events.size(); ++i) {
        const Event& e = events[i];
        cout << human_datetime(e.ts) << " | " << shorten_path(e.directory) << " | "
             << e.type << " | " << e.process << " | " << shorten_path(e.target) << "\n";
    }
    return 0;
}

static int cmd_open(vector<string> args) {
    if (args.empty()) {
        cerr << "usage: gravity open PATH\n";
        return 2;
    }
    string cmd = "xdg-open '" + realpath_or_self(args[0]) + "' >/dev/null 2>&1 &";
    system(cmd.c_str());
    return 0;
}

static void usage() {
    cout << "Gravity — directory activity and time inference\n\n";
    cout << "Commands:\n";
    cout << "  gravity watch PATH...\n";
    cout << "  gravity unwatch PATH...\n";
    cout << "  gravity status\n";
    cout << "  gravity daemon\n";
    cout << "  gravity install-service\n";
    cout << "  gravity uninstall-service\n";
    cout << "  gravity month [YYYY-MM] [--json OUT] [--html] [--html-out OUT]\n";
    cout << "  gravity top [YYYY-MM]\n";
    cout << "  gravity sessions [YYYY-MM]\n";
    cout << "  gravity timeline [YYYY-MM]\n";
    cout << "  gravity open PATH\n";
}

int main(int argc, char** argv) {
    ensure_dirs();
    if (argc < 2) {
        usage();
        return 0;
    }
    string cmd = argv[1];
    vector<string> args;
    for (int i = 2; i < argc; ++i) args.push_back(argv[i]);

    if (cmd == "watch") return cmd_watch(args);
    if (cmd == "unwatch") return cmd_unwatch(args);
    if (cmd == "status") return cmd_status();
    if (cmd == "daemon") return cmd_daemon();
    if (cmd == "install-service") return cmd_install_service();
    if (cmd == "uninstall-service") return cmd_uninstall_service();
    if (cmd == "month") return cmd_month(args);
    if (cmd == "top") return cmd_top(args);
    if (cmd == "sessions") return cmd_sessions(args);
    if (cmd == "timeline") return cmd_timeline(args);
    if (cmd == "open") return cmd_open(args);
    if (cmd == "help" || cmd == "--help" || cmd == "-h") {
        usage();
        return 0;
    }

    cerr << "unknown command: " << cmd << "\n";
    usage();
    return 2;
}
