// peer_daemon.cpp
// Background scanner/enforcer. Loads nodes from config.json.
// Writes shared memory. Display attaches separately.
//
// Build: g++ -std=c++17 -pthread -O2 -o peer_daemon peer_daemon.cpp -lrt

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include "git_version.h"
#include <vector>
#include <algorithm>
#include <cctype>
#include <map>
#include <mutex>
#include <thread>

// =============================================================================
// Shared memory layout
// =============================================================================
static const int MAX_PEERS_PER_NODE = 512;
static const int MAX_NODES = 32;
static const char* SHM_NAME = "/bitcoin_peer_scanner_shm";
static const char* STATE_FILE = "dry_run.state";
static const char* HASH_FILE  = "last_githash.state";
static const char* CONFIG_FILE = "config.json";

struct PeerInfo {
    char addr[96];
    char ip[80];
    int nodeid;
    bool has_blake2b;
    bool has_rdts;
    bool banned;
    bool is_keep;
    bool is_inject;
    char subver[20];
    uint32_t first_responder_count;
    uint32_t connected_seconds;
    float score_per_100;
};

struct NodeState {
    char name[32];
    PeerInfo peers[MAX_PEERS_PER_NODE];
    int peer_count;
    int banned_count;
    int blocks_height;
    int headers_height;
    char last_error[64];
};

struct SharedState {
    pthread_mutex_t mutex;
    std::atomic<bool> dry_run;
    std::atomic<bool> parse_mismatch;
    std::atomic<bool> daemon_running;
    std::atomic<uint32_t> fidget;   // incremented every second by daemon
    int node_count;
    NodeState nodes[MAX_NODES];
    char config_error[128];
    char config_path[256];
};

// =============================================================================
// Config
// =============================================================================
struct NodeConfig {
    std::string name;
    std::string host;
    int port = 8332;
    std::string rpcuser;
    std::string rpcpassword;
    std::string cookie_path;
    std::vector<std::string> keep_peers;   // "ip:port" or "ip" (defaults to :8333)
    std::vector<std::string> inject_peers; // always addnode these
    bool enforce_blake2b = false;
    bool enforce_bip110 = false;
};

static std::vector<NodeConfig> NODES;
static SharedState* shm = nullptr;
static std::atomic<bool> running{true};
static std::vector<std::thread> scanner_threads;
static std::atomic<int> config_generation{0};

// forward declaration
static void scanner_thread(NodeConfig cfg, int node_idx, int gen);

static std::atomic<int> scanner_generation{0};

static void stop_scanners() {
    // Bump generation so old threads exit on their next check.
    // Detach them so we never join a thread that may already be gone.
    scanner_generation.fetch_add(1);
    for (auto& t : scanner_threads) {
        if (t.joinable()) t.detach();
    }
    scanner_threads.clear();
}

static void start_scanners() {
    stop_scanners();
    int gen = scanner_generation.load();
    for (size_t i = 0; i < NODES.size(); ++i)
        scanner_threads.emplace_back(scanner_thread, NODES[i], (int)i, gen);
}

static const int SCAN_INTERVAL_SEC = 8;

// Persistent peer tracking (across scans)
struct PeerTrack {
    uint32_t first_responder_count = 0;
    uint32_t connected_seconds = 0;
    uint32_t last_seen_scan = 0;
    uint32_t last_block_announcement = 0;
    std::string latest_json;   // most recent getpeerinfo object for this peer
    std::string last_addr;
};
static std::string peer_key(const PeerInfo& p) {
    // Key by full address (ip:port) so 127.0.0.1:8333 and 127.0.0.1:8334 are distinct
    std::string k = p.addr[0] ? p.addr : p.ip;
    for (char& ch : k) if (ch == ':' || ch == '/' || ch == '\\' || ch == '[' || ch == ']') ch = '_';
    return k;
}
static std::map<std::string, PeerTrack> peer_registry;
static std::mutex registry_mutex;
static uint32_t scan_counter = 0;
// Extract a port from an address string
static std::string normalize_addr(const std::string& raw);
static const char* PEER_DB = "peers.db";

static std::string port_of(const std::string& addr) {
    auto c = addr.rfind(':');
    return (c != std::string::npos) ? addr.substr(c+1) : "";
}

// True if two nodes have complementary 127.0.0.1 connections
// (A sees addr:X addrbind:Y, B sees addr:Y addrbind:X)
static bool is_mutual_local(const std::string& addr, const std::string& raw_json, int my_idx) {
    std::string my_port = port_of(addr);
    if (my_port.empty()) return false;
    // find addrbind or addrlocal near this peer in the JSON
    size_t pos = raw_json.find(std::string("\"addr\":\"") + addr);
    std::string bind_port;
    if (pos != std::string::npos) {
        for (const char* key : {"\"addrbind\"", "\"addrlocal\""}) {
            size_t bp = raw_json.find(key, pos);
            if (bp != std::string::npos && bp < pos + 500) {
                size_t q1 = raw_json.find('"', bp + strlen(key) + 1);
                size_t q2 = (q1 != std::string::npos) ? raw_json.find('"', q1+1) : std::string::npos;
                if (q1 != std::string::npos && q2 != std::string::npos)
                    bind_port = port_of(raw_json.substr(q1+1, q2-q1-1));
                if (!bind_port.empty()) break;
            }
        }
    }
    if (bind_port.empty()) return false;
    // check other nodes for the reverse pair
    pthread_mutex_lock(&shm->mutex);
    for (int n = 0; n < shm->node_count && n < MAX_NODES; ++n) {
        if (n == my_idx) continue;
        for (int i = 0; i < shm->nodes[n].peer_count; ++i) {
            const auto& op = shm->nodes[n].peers[i];
            if (normalize_addr(op.addr) != "127.0.0.1" && normalize_addr(op.addr) != "::1") continue;
            if (port_of(op.addr) == bind_port) {
                pthread_mutex_unlock(&shm->mutex);
                return true;
            }
        }
    }
    pthread_mutex_unlock(&shm->mutex);
    return false;
}

// grace counter for non-mutual 127.0.0.1 peers (keyed by addr)
static std::map<std::string, int> local_grace;

static void load_peer_db() {
    std::ifstream f(PEER_DB);
    if (!f) return;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        // format: ip|first_resp|conn_sec|last_ann|last_addr
        size_t p1 = line.find('|');
        if (p1 == std::string::npos) continue;
        size_t p2 = line.find('|', p1+1);
        size_t p3 = line.find('|', p2+1);
        size_t p4 = line.find('|', p3+1);
        if (p2 == std::string::npos || p3 == std::string::npos) continue;
        std::string ip = line.substr(0, p1);
        PeerTrack t;
        t.first_responder_count = std::atoi(line.c_str() + p1 + 1);
        t.connected_seconds = std::atoi(line.c_str() + p2 + 1);
        t.last_block_announcement = std::atoi(line.c_str() + p3 + 1);
        if (p4 != std::string::npos) t.last_addr = line.substr(p4 + 1);
        peer_registry[ip] = t;
    }
}

static void save_peer_db() {
    std::lock_guard<std::mutex> lock(registry_mutex);
    std::ofstream f(PEER_DB, std::ios::trunc);
    if (!f) return;
    f << "# key|first_resp|conn_sec|last_announcement|last_addr\n";
    for (const auto& [key, t] : peer_registry) {
        f << key << '|' << t.first_responder_count << '|' << t.connected_seconds
          << '|' << t.last_block_announcement << '|' << t.last_addr << '\n';
    }
}

static void update_tracking(std::vector<PeerInfo>& peers, const std::string& raw_json) {
    std::lock_guard<std::mutex> lock(registry_mutex);
    scan_counter++;
    for (auto& p : peers) {
        auto& t = peer_registry[peer_key(p)];
        t.connected_seconds += SCAN_INTERVAL_SEC;
        t.last_seen_scan = scan_counter;
        t.last_addr = p.addr;
        // write full peer JSON object to a side file for the display
        size_t pos = raw_json.find(std::string("\"addr\":\"") + p.addr);
        if (pos != std::string::npos) {
            size_t obj_start = raw_json.rfind('{', pos);
            int depth = 0;
            size_t obj_end = obj_start;
            bool in_str = false;
            for (; obj_end < raw_json.size(); ++obj_end) {
                char c = raw_json[obj_end];
                if (c == '"' && (obj_end == 0 || raw_json[obj_end-1] != '\\')) in_str = !in_str;
                if (in_str) continue;
                if (c == '{') depth++;
                else if (c == '}') {
                    depth--;
                    if (depth == 0) break;
                }
            }
            if (obj_start != std::string::npos && obj_end < raw_json.size()) {
                t.latest_json = raw_json.substr(obj_start, obj_end - obj_start + 1);
                std::string safe = peer_key(p);
                std::ofstream jf(std::string("peer_json_") + safe + ".txt");
                if (jf) jf << t.latest_json;
            }
            size_t ann = raw_json.find("\"last_block_announcement\"", pos);
            if (ann != std::string::npos && ann < pos + 2000) {
                size_t colon = raw_json.find(':', ann);
                if (colon != std::string::npos) {
                    uint32_t ts = std::atoi(raw_json.c_str() + colon + 1);
                    if (ts > t.last_block_announcement && ts > 0) {
                        t.first_responder_count++;
                        t.last_block_announcement = ts;
                    }
                }
            }
        }
        p.first_responder_count = t.first_responder_count;
        p.connected_seconds = t.connected_seconds;
        float blocks_seen = std::max(1.0f, t.connected_seconds / 600.0f);
        p.score_per_100 = (t.first_responder_count * 100.0f) / blocks_seen;
    }
}

static void write_csv() {
    std::lock_guard<std::mutex> lock(registry_mutex);
    std::vector<std::pair<std::string, PeerTrack>> sorted(peer_registry.begin(), peer_registry.end());
    std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) {
        float ba = std::max(1.0f, a.second.connected_seconds / 600.0f);
        float bb = std::max(1.0f, b.second.connected_seconds / 600.0f);
        float sa = (a.second.first_responder_count * 100.0f) / ba;
        float sb = (b.second.first_responder_count * 100.0f) / bb;
        return sa > sb;
    });
    std::ofstream f("peers_seen.csv");
    if (!f) return;
    f << "addr,score_per_100\n";
    for (const auto& [ip, t] : sorted) {
        float blocks = std::max(1.0f, t.connected_seconds / 600.0f);
        float score = (t.first_responder_count * 100.0f) / blocks;
        f << ip << " # score=" << score << " first_resp=" << t.first_responder_count
          << " conn_sec=" << t.connected_seconds << "\n";
    }
}
// Normalize an address for matching: strip port, return canonical host.
// Handles IPv4, [IPv6]:port, IPv6:port, onion, i2p, hostnames.
static std::string normalize_addr(const std::string& raw) {
    std::string s = raw;
    // strip trailing port if present
    if (s.size() > 2 && s[0] == '[') {
        auto end = s.find(']');
        if (end != std::string::npos) return s.substr(1, end - 1);
    }
    // onion / i2p / hostname: last colon separates port
    if (s.find(".onion") != std::string::npos || s.find(".i2p") != std::string::npos ||
        s.find('.') != std::string::npos) {
        auto c = s.rfind(':');
        if (c != std::string::npos && c > 0 && std::isdigit(s[c+1]))
            return s.substr(0, c);
        return s;
    }
    // bare IPv6 (contains multiple colons, no brackets)
    if (std::count(s.begin(), s.end(), ':') > 1) {
        // if last segment looks like a port (numeric, short), strip it
        auto c = s.rfind(':');
        if (c != std::string::npos) {
            std::string tail = s.substr(c + 1);
            if (tail.size() <= 5 && !tail.empty() &&
                std::all_of(tail.begin(), tail.end(), ::isdigit))
                return s.substr(0, c);
        }
        return s;
    }
    // IPv4:port
    auto c = s.rfind(':');
    if (c != std::string::npos) return s.substr(0, c);
    return s;
}

static bool is_onion_or_i2p(const std::string& addr) {
    return addr.find(".onion") != std::string::npos || addr.find(".i2p") != std::string::npos;
}
static const char* BLAKE2B_FLAG = "BLAKE2B?";
static const char* RDTS_FLAG    = "REDUCED_DATA?";
static const int RDTS_HEIGHT = 961632;
static const int BLAKE2B_HEIGHT = 961640;
static const int BAN_SECONDS = 86400 * 7;
static const int MIN_PEERS_IBD = 8;

static int extract_chain_height(const std::string& json, const char* key) {
    size_t p = json.find(std::string("\"") + key + "\"");
    if (p == std::string::npos) return -1;
    p = json.find(':', p);
    if (p == std::string::npos) return -1;
    return std::atoi(json.c_str() + p + 1);
}

// =============================================================================
// Minimal JSON config loader
// =============================================================================
static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    size_t b = s.find_last_not_of(" \t\r\n");
    return (a == std::string::npos) ? "" : s.substr(a, b - a + 1);
}

static std::string extract_string(const std::string& obj, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    size_t pos = obj.find(needle);
    if (pos == std::string::npos) return "";
    pos = obj.find(':', pos);
    if (pos == std::string::npos) return "";
    pos = obj.find('"', pos);
    if (pos == std::string::npos) return "";
    size_t end = obj.find('"', pos + 1);
    if (end == std::string::npos) return "";
    return obj.substr(pos + 1, end - pos - 1);
}

static int extract_int(const std::string& obj, const std::string& key, int def = 0) {
    std::string needle = "\"" + key + "\"";
    size_t pos = obj.find(needle);
    if (pos == std::string::npos) return def;
    pos = obj.find(':', pos);
    if (pos == std::string::npos) return def;
    pos++;
    while (pos < obj.size() && (obj[pos] == ' ' || obj[pos] == '\t')) pos++;
    return std::atoi(obj.c_str() + pos);
}

static bool extract_bool(const std::string& obj, const std::string& key, bool def = false) {
    std::string needle = "\"" + key + "\"";
    size_t pos = obj.find(needle);
    if (pos == std::string::npos) return def;
    pos = obj.find(':', pos);
    if (pos == std::string::npos) return def;
    pos++;
    while (pos < obj.size() && (obj[pos] == ' ' || obj[pos] == '\t')) pos++;
    return obj.compare(pos, 4, "true") == 0;
}

static std::vector<std::string> extract_string_array(const std::string& obj, const std::string& key) {
    std::vector<std::string> out;
    std::string needle = "\"" + key + "\"";
    size_t pos = obj.find(needle);
    if (pos == std::string::npos) return out;
    size_t arr = obj.find('[', pos);
    if (arr == std::string::npos) return out;
    size_t end = obj.find(']', arr);
    if (end == std::string::npos) return out;
    std::string inside = obj.substr(arr + 1, end - arr - 1);
    size_t p = 0;
    while ((p = inside.find('"', p)) != std::string::npos) {
        size_t q = inside.find('"', p + 1);
        if (q == std::string::npos) break;
        std::string s = inside.substr(p + 1, q - p - 1);
        if (!s.empty()) out.push_back(s);
        p = q + 1;
    }
    return out;
}

static bool load_config(const std::string& path, std::string& error_out) {
    error_out.clear();
    std::ifstream f(path);
    if (!f) {
        error_out = "Cannot open config file";
        return false;
    }
    std::stringstream ss;
    ss << f.rdbuf();
    std::string json = ss.str();

    if (json.find('{') == std::string::npos) {
        error_out = "Not valid JSON (no object)";
        return false;
    }

    size_t nodes_pos = json.find("\"nodes\"");
    if (nodes_pos == std::string::npos) {
        error_out = "Missing \"nodes\" array";
        return false;
    }
    size_t arr_start = json.find('[', nodes_pos);
    if (arr_start == std::string::npos) {
        error_out = "Malformed nodes array";
        return false;
    }
    // find matching ] for the nodes array
    int arr_depth = 0;
    size_t arr_end = arr_start;
    bool in_str = false;
    for (; arr_end < json.size(); ++arr_end) {
        char c = json[arr_end];
        if (c == '"' && (arr_end == 0 || json[arr_end-1] != '\\')) in_str = !in_str;
        if (in_str) continue;
        if (c == '[') arr_depth++;
        else if (c == ']') {
            arr_depth--;
            if (arr_depth == 0) break;
        }
    }
    if (arr_end >= json.size() || arr_depth != 0) {
        error_out = "Unclosed nodes array";
        return false;
    }

    std::string arr = json.substr(arr_start + 1, arr_end - arr_start - 1);
    size_t pos = 0;
    std::vector<NodeConfig> new_nodes;
    while ((pos = arr.find('{', pos)) != std::string::npos) {
        // match braces, ignoring strings
        int depth = 0;
        size_t end = pos;
        bool in_str = false;
        for (; end < arr.size(); ++end) {
            char c = arr[end];
            if (c == '"' && (end == 0 || arr[end-1] != '\\')) in_str = !in_str;
            if (in_str) continue;
            if (c == '{') depth++;
            else if (c == '}') {
                depth--;
                if (depth == 0) break;
            }
        }
        if (end >= arr.size() || depth != 0) {
            error_out = "Unclosed object in nodes array";
            return false;
        }
        std::string obj = arr.substr(pos, end - pos + 1);

        NodeConfig n;
        n.name = extract_string(obj, "name");
        n.host = extract_string(obj, "host");
        n.port = extract_int(obj, "port", 8332);
        n.rpcuser = extract_string(obj, "rpcuser");
        n.rpcpassword = extract_string(obj, "rpcpassword");
        n.cookie_path = extract_string(obj, "cookie_path");
        n.keep_peers = extract_string_array(obj, "keep_peers");
        n.inject_peers = extract_string_array(obj, "inject_peers");
        // backward compat: single keep_ip
        std::string single = extract_string(obj, "keep_ip");
        if (!single.empty()) n.keep_peers.push_back(single);
        n.enforce_blake2b = extract_bool(obj, "enforce_blake2b");
        n.enforce_bip110 = extract_bool(obj, "enforce_bip110");

        if (n.name.empty() || n.host.empty()) {
            error_out = "Node missing name or host";
            return false;
        }
        if (n.port < 1 || n.port > 65535) {
            error_out = "Invalid port on node " + n.name;
            return false;
        }

        new_nodes.push_back(n);
        pos = end + 1;
        if (new_nodes.size() >= MAX_NODES) break;
    }

    if (new_nodes.empty()) {
        error_out = "No valid nodes found";
        return false;
    }

    NODES = std::move(new_nodes);
    return true;
}

// =============================================================================
// Dry-run file helpers
// =============================================================================
static void save_dry_run();
static void load_dry_run() {
    std::ifstream f(STATE_FILE);
    if (!f) {
        shm->dry_run.store(true);
        return;
    }
    int v = 1;
    f >> v;
    shm->dry_run.store(v != 0);
}

static void check_githash_and_force_dry() {
    std::string prev;
    {
        std::ifstream f(HASH_FILE);
        if (f) std::getline(f, prev);
    }
    std::string cur = GIT_COMMIT_HASH;
    if (prev != cur) {
        shm->dry_run.store(true);
        save_dry_run();
        std::cout << "[SAFETY] Git hash changed (" << (prev.empty() ? "none" : prev)
                  << " -> " << cur << "). Forced DRY-RUN.\n";
    }
    std::ofstream out(HASH_FILE, std::ios::trunc);
    if (out) out << cur << "\n";
}

static void save_dry_run() {
    std::ofstream f(STATE_FILE, std::ios::trunc);
    if (f) f << (shm->dry_run.load() ? 1 : 0) << "\n";
}

// =============================================================================
// Minimal HTTP + JSON-RPC
// =============================================================================
static std::string read_cookie(const std::string& path) {
    FILE* f = fopen(path.c_str(), "r");
    if (!f) return "";
    char buf[256] = {};
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return ""; }
    fclose(f);
    std::string s(buf);
    while (!s.empty() && (s.back()=='\n' || s.back()=='\r')) s.pop_back();
    return s;
}

static std::string base64_encode(const std::string& in) {
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(tbl[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(tbl[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

static std::string http_post(const std::string& host, int port,
                              const std::string& auth_header,
                              const std::string& body) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return "";
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock); return "";
    }

    std::ostringstream req;
    req << "POST / HTTP/1.1\r\nHost: " << host << "\r\n"
        << "Content-Type: application/json\r\nContent-Length: " << body.size() << "\r\n"
        << "Authorization: " << auth_header << "\r\nConnection: close\r\n\r\n" << body;

    std::string r = req.str();
    send(sock, r.data(), r.size(), 0);

    std::string resp;
    char buf[4096];
    while (true) {
        int n = recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) break;
        resp.append(buf, n);
    }
    close(sock);
    auto pos = resp.find("\r\n\r\n");
    return pos == std::string::npos ? "" : resp.substr(pos + 4);
}

static std::vector<PeerInfo> parse_peers(const std::string& json) {
    std::vector<PeerInfo> out;
    size_t pos = 0;
    // Look for peer-level "addr" fields. Real peer addrs contain ':' or '.' or are onion/i2p.
    // Skip anything that looks like a message-type key (feefilter, alert, getaddr, block, etc.)
    while ((pos = json.find("\"addr\"", pos)) != std::string::npos && out.size() < MAX_PEERS_PER_NODE) {
        // Make sure this is a key, not a substring
        if (pos > 0 && json[pos-1] != '{' && json[pos-1] != ',' && json[pos-1] != ' ' && json[pos-1] != '\n') {
            pos += 6;
            continue;
        }
        size_t colon = json.find(':', pos);
        if (colon == std::string::npos) break;
        size_t q1 = json.find('"', colon);
        if (q1 == std::string::npos) break;
        size_t q2 = json.find('"', q1 + 1);
        if (q2 == std::string::npos) break;

        std::string addr = json.substr(q1 + 1, q2 - q1 - 1);

        // Filter out non-address strings
        bool looks_like_addr = false;
        if (addr.find(':') != std::string::npos) looks_like_addr = true;          // ip:port or [ipv6]:port
        else if (addr.find('.') != std::string::npos) looks_like_addr = true;     // hostname
        else if (addr.size() > 16 && addr.find("onion") != std::string::npos) looks_like_addr = true;
        else if (addr.size() > 16 && addr.find("i2p") != std::string::npos) looks_like_addr = true;

        if (!looks_like_addr || addr == "addr" || addr.find("feefilter") != std::string::npos ||
            addr.find("alert") != std::string::npos || addr.find("getaddr") != std::string::npos ||
            addr.find("block") != std::string::npos || addr.find("cmpctblock") != std::string::npos) {
            pos = q2 + 1;
            continue;
        }

        PeerInfo p{};
        strncpy(p.addr, addr.c_str(), sizeof(p.addr)-1);
        std::string ip = normalize_addr(addr);
        strncpy(p.ip, ip.c_str(), sizeof(p.ip)-1);
        p.nodeid = -1;
        // extract id near this addr
        size_t idpos = json.rfind("\"id\"", pos);
        if (idpos != std::string::npos && idpos > pos - 200) {
            size_t colon = json.find(':', idpos);
            if (colon != std::string::npos) p.nodeid = std::atoi(json.c_str() + colon + 1);
        }

        // servicesnames must appear soon after this addr
        size_t sn = json.find("\"servicesnames\"", pos);
        if (sn != std::string::npos && sn < pos + 8000) {
            size_t arr = json.find('[', sn);
            size_t endarr = json.find(']', arr);
            if (arr != std::string::npos && endarr != std::string::npos) {
                std::string names = json.substr(arr, endarr - arr);
                bool bit28 = names.find("2^28") != std::string::npos ||
                             names.find("268435456") != std::string::npos;
                bool bit27 = names.find("2^27") != std::string::npos ||
                             names.find("134217728") != std::string::npos;
                p.has_blake2b = names.find(BLAKE2B_FLAG) != std::string::npos || bit28;
                p.has_rdts    = names.find(RDTS_FLAG) != std::string::npos || bit27 || bit28;
            }
        }
        // extract subver near this addr
        size_t sv = json.find("\"subver\"", pos);
        if (sv != std::string::npos && sv < pos + 8000) {
            size_t q1 = json.find('"', sv + 8);
            size_t q2 = (q1 != std::string::npos) ? json.find('"', q1+1) : std::string::npos;
            if (q1 != std::string::npos && q2 != std::string::npos) {
                std::string s = json.substr(q1+1, std::min((size_t)16, q2-q1-1));
                strncpy(p.subver, s.c_str(), sizeof(p.subver)-1);
            }
        }
        out.push_back(p);
        pos = q2 + 1;
    }
    return out;
}

static std::string rpc_call(const NodeConfig& n, const std::string& method,
                             const std::string& params_json = "[]") {
    std::string auth;
    if (!n.cookie_path.empty()) {
        std::string cookie = read_cookie(n.cookie_path);
        if (!cookie.empty()) auth = "Basic " + base64_encode(cookie);
    }
    if (auth.empty() && !n.rpcuser.empty())
        auth = "Basic " + base64_encode(n.rpcuser + ":" + n.rpcpassword);
    if (auth.empty()) return "";

    std::string body = "{\"jsonrpc\":\"1.0\",\"id\":\"scanner\",\"method\":\"" +
                       method + "\",\"params\":" + params_json + "}";
    return http_post(n.host, n.port, auth, body);
}

static void apply_ban(const NodeConfig& n, const std::string& addr, int nodeid) {
    if (shm->dry_run.load() || shm->parse_mismatch.load()) return;
    // prefer nodeid — uniquely identifies onion/127.0.0.1 peers
    if (nodeid >= 0) {
        rpc_call(n, "disconnectnode", "[\"\"," + std::to_string(nodeid) + "]");
    } else {
        rpc_call(n, "disconnectnode", "[\"" + addr + "\"]");
    }
}

static void ensure_keep_and_inject(const NodeConfig& n, const std::vector<PeerInfo>& current) {
    auto already = [&](const std::string& peer) {
        for (const auto& p : current) {
            if (normalize_addr(p.addr) != normalize_addr(peer)) continue;
            if (normalize_addr(peer) == "127.0.0.1" || normalize_addr(peer) == "::1") {
                auto pc = std::string(p.addr).rfind(':');
                auto ic = peer.rfind(':');
                if (pc != std::string::npos && ic != std::string::npos &&
                    std::string(p.addr).substr(pc) == peer.substr(ic)) return true;
            } else {
                return true;
            }
        }
        return false;
    };
    auto do_add = [&](const std::string& peer) {
        // only addnode entries that have an explicit port
        if (peer.find(':') == std::string::npos) return;
        if (already(peer)) return;
        std::string host = normalize_addr(peer);
        rpc_call(n, "setban", "[\"" + host + "\",\"remove\"]");
        rpc_call(n, "addnode", "[\"" + peer + "\",\"add\"]");
        rpc_call(n, "addnode", "[\"" + peer + "\",\"onetry\"]");
        std::cout << "[INJECT] " << n.name << " addnode " << peer << "\n";
    };
    for (const auto& k : n.keep_peers) do_add(k);
    for (const auto& i : n.inject_peers) do_add(i);
}

// =============================================================================
// Scanner
// =============================================================================
static void scanner_thread(NodeConfig cfg, int node_idx, int gen) {
    while (running.load() && scanner_generation.load() == gen) {
        std::string peer_resp = rpc_call(cfg, "getpeerinfo");
        std::string net_resp  = rpc_call(cfg, "getnetworkinfo");
        std::string chain_resp = rpc_call(cfg, "getblockchaininfo");
        std::vector<PeerInfo> peers;
        std::string err;
        int reported_connections = -1;
        int blocks_height = -1;
        int headers_height = -1;

        if (peer_resp.empty()) {
            err = "RPC failed";
        } else {
            peers = parse_peers(peer_resp);
        }

        if (!chain_resp.empty()) {
            blocks_height = extract_chain_height(chain_resp, "blocks");
            headers_height = extract_chain_height(chain_resp, "headers");
        }

        // extract connections from getnetworkinfo
        if (!net_resp.empty()) {
            size_t p = net_resp.find("\"connections\"");
            if (p != std::string::npos) {
                p = net_resp.find(':', p);
                if (p != std::string::npos) {
                    reported_connections = std::atoi(net_resp.c_str() + p + 1);
                }
            }
        }

        bool mismatch = false;
        if (reported_connections >= 0 && (int)peers.size() != reported_connections) {
            mismatch = true;
            err = "peer count mismatch (" + std::to_string(peers.size()) +
                  " parsed vs " + std::to_string(reported_connections) + " reported)";
        }
        shm->parse_mismatch.store(mismatch);

        int banned = 0;
        int total = (int)peers.size();
        int banned_this_pass = 0;
        for (auto& p : peers) {
            bool is_keep = false;
            for (const auto& k : cfg.keep_peers) {
                std::string pa = p.addr, ka = k;
                if (normalize_addr(pa) != normalize_addr(ka)) continue;
                // localhost: match if ports equal, or config has no port, or peer is on 8333
                if (normalize_addr(pa) == "127.0.0.1" || normalize_addr(pa) == "::1") {
                    auto pc = pa.rfind(':'), kc = ka.rfind(':');
                    bool port_ok = (kc == std::string::npos) ||
                                   (pc != std::string::npos && pa.substr(pc) == ka.substr(kc)) ||
                                   (pc != std::string::npos && pa.substr(pc) == ":8333");
                    if (port_ok) { is_keep = true; break; }
                } else {
                    is_keep = true; break;
                }
            }
            bool is_inject = false;
            for (const auto& inj : cfg.inject_peers) {
                std::string pa = p.addr, ia = inj;
                if (normalize_addr(pa) != normalize_addr(ia)) continue;
                if (normalize_addr(pa) == "127.0.0.1" || normalize_addr(pa) == "::1") {
                    auto pc = pa.rfind(':'), ic = ia.rfind(':');
                    bool port_ok = (ic == std::string::npos) ||
                                   (pc != std::string::npos && pa.substr(pc) == ia.substr(ic)) ||
                                   (pc != std::string::npos && pa.substr(pc) == ":8333");
                    if (port_ok) { is_inject = true; break; }
                } else {
                    is_inject = true; break;
                }
            }
            if (!is_keep && !is_inject &&
                (normalize_addr(p.addr) == "127.0.0.1" || normalize_addr(p.addr) == "::1")) {
                if (is_mutual_local(p.addr, peer_resp, node_idx)) {
                    is_keep = true;  // mutual internal pair
                } else {
                    int& g = local_grace[p.addr];
                    g++;
                    if (g < 3) {
                        is_keep = true;  // grace period
                        std::cout << "[LOCAL] " << cfg.name << " " << p.addr
                                  << " grace " << g << "/3\n";
                    } else {
                        std::cout << "[LOCAL] " << cfg.name << " " << p.addr
                                  << " not mutual, applying rules\n";
                    }
                }
            }
            p.is_keep = is_keep;
            p.is_inject = is_inject;
            if (is_keep || is_inject) continue;

            bool should_ban = false;
            int sync_h = (blocks_height >= 0) ? blocks_height : headers_height;
            bool in_ibd = (sync_h < RDTS_HEIGHT) || (headers_height > 0 && blocks_height >= 0 && blocks_height + 10 < headers_height);

            if (cfg.enforce_blake2b) {
                if (sync_h < RDTS_HEIGHT) {
                    int non_blake = 0;
                    for (const auto& q : peers) if (!q.has_blake2b) non_blake++;
                    if (!p.has_blake2b && non_blake > total / 2)
                        should_ban = true;
                } else if (sync_h < BLAKE2B_HEIGHT) {
                    if (!p.has_blake2b) should_ban = true;
                } else {
                    if (!p.has_blake2b) should_ban = true;
                }
            } else if (cfg.enforce_bip110) {
                if (sync_h < RDTS_HEIGHT) {
                    // pre-RDTS: do not ban
                } else {
                    if (!p.has_blake2b && !p.has_rdts) should_ban = true;
                }
            }

            // IBD floor: never ban below MIN_PEERS_IBD
            if (should_ban && in_ibd) {
                int remaining = total - banned_this_pass - 1;
                if (remaining < MIN_PEERS_IBD) should_ban = false;
            }

            if (should_ban) {
                p.banned = true;
                banned++;
                banned_this_pass++;
                apply_ban(cfg, p.addr, p.nodeid);
            }
        }
        ensure_keep_and_inject(cfg, peers);

        update_tracking(peers, peer_resp);
        if (scan_counter % 10 == 0) write_csv();

        pthread_mutex_lock(&shm->mutex);
        NodeState& st = shm->nodes[node_idx];
        strncpy(st.name, cfg.name.c_str(), sizeof(st.name)-1);
        st.peer_count = std::min((int)peers.size(), MAX_PEERS_PER_NODE);
        st.blocks_height = blocks_height;
        st.headers_height = headers_height;
        for (int i = 0; i < st.peer_count; ++i) st.peers[i] = peers[i];
        st.banned_count = banned;
        strncpy(st.last_error, err.c_str(), sizeof(st.last_error)-1);
        pthread_mutex_unlock(&shm->mutex);

        for (int i = 0; i < SCAN_INTERVAL_SEC && running.load() && scanner_generation.load() == gen; ++i)
            std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

// =============================================================================
// Config watcher (live reload + dry interlock)
// =============================================================================
static void config_watcher(const std::string& path) {
    struct stat st{};
    time_t last_sec = 0;
    long last_nsec = 0;

    if (stat(path.c_str(), &st) == 0) {
        last_sec = st.st_mtim.tv_sec;
        last_nsec = st.st_mtim.tv_nsec;
    }

    while (running.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(800));
        if (stat(path.c_str(), &st) != 0) continue;

        if (st.st_mtim.tv_sec == last_sec && st.st_mtim.tv_nsec == last_nsec) continue;

        std::cout << "[CONFIG] " << path << " changed, validating...\n";

        std::string err;
        std::vector<NodeConfig> backup = NODES;
        bool ok = load_config(path, err);

        pthread_mutex_lock(&shm->mutex);
        if (!ok) {
            strncpy(shm->config_error, err.c_str(), sizeof(shm->config_error)-1);
            shm->config_error[sizeof(shm->config_error)-1] = '\0';
            NODES = std::move(backup); // restore
            std::cerr << "[CONFIG] REJECTED: " << err << " (staying on previous config)\n";
        } else {
            shm->config_error[0] = '\0';
            shm->node_count = (int)NODES.size();
            // Dry interlock: force dry-run on any successful reload
            shm->dry_run.store(true);
            save_dry_run();
            std::cout << "[CONFIG] RELOADED " << NODES.size() << " node(s). Forced DRY-RUN. Restarting scanners.\n";
            pthread_mutex_unlock(&shm->mutex);
            start_scanners();
            pthread_mutex_lock(&shm->mutex);
        }
        pthread_mutex_unlock(&shm->mutex);

        last_sec = st.st_mtim.tv_sec;
        last_nsec = st.st_mtim.tv_nsec;
    }
}

// =============================================================================
int main(int argc, char** argv) {
    std::string cfg_path = (argc > 1) ? argv[1] : CONFIG_FILE;

    std::string init_err;
    if (!load_config(cfg_path, init_err)) {
        std::cerr << "Initial config failed: " << init_err << "\n";
        return 1;
    }

    int fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
    if (fd < 0) { perror("shm_open"); return 1; }
    if (ftruncate(fd, sizeof(SharedState)) < 0) { perror("ftruncate"); return 1; }
    shm = (SharedState*)mmap(nullptr, sizeof(SharedState), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (shm == MAP_FAILED) { perror("mmap"); return 1; }
    close(fd);

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(&shm->mutex, &attr);
    pthread_mutexattr_destroy(&attr);

    shm->node_count = (int)NODES.size();
    shm->daemon_running.store(true);
    shm->parse_mismatch.store(false);
    shm->fidget.store(0);
    shm->config_error[0] = '\0';
    strncpy(shm->config_path, cfg_path.c_str(), sizeof(shm->config_path)-1);
    load_dry_run();
    check_githash_and_force_dry();
    load_peer_db();

    std::thread db_saver([] {
        while (running.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(60));
            if (running.load()) save_peer_db();
        }
    });

    std::vector<std::thread> threads;
    start_scanners();

    std::thread watcher(config_watcher, cfg_path);

    std::cout << "Bitcoin Peer Scanner " << GIT_COMMIT_HASH << "\n";
    std::cout << "Daemon running. Shared memory: " << SHM_NAME << "\n";
    std::cout << "Nodes: " << NODES.size() << "  Dry-run: " << (shm->dry_run.load() ? "ON" : "OFF") << "\n";
    for (const auto& n : NODES) {
        std::cout << "  " << n.name << " keep=[";
        for (size_t i = 0; i < n.keep_peers.size(); ++i) std::cout << (i?",":"") << n.keep_peers[i];
        std::cout << "] inject=[";
        for (size_t i = 0; i < n.inject_peers.size(); ++i) std::cout << (i?",":"") << n.inject_peers[i];
        std::cout << "]\n";
    }
    std::cout << "Start peer_display to view. Ctrl+C to stop.\n";

    while (running.load()) {
        shm->daemon_running.store(true);
        shm->fidget.fetch_add(1);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    running.store(false);
    shm->daemon_running.store(false);
    save_dry_run();
    save_peer_db();
    for (auto& t : scanner_threads) if (t.joinable()) t.join();
    if (db_saver.joinable()) db_saver.join();
    if (watcher.joinable()) watcher.join();

    munmap(shm, sizeof(SharedState));
    return 0;
}
