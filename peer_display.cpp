// peer_display.cpp
// Separate live display. Attaches to shared memory created by peer_daemon.
// Ctrl+R toggles dry-run. Left/Right cycles node pages. TAB toggles justify.
// Mouse wheel scrolls. Heartbeat via fidget.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <sys/mman.h>
#include <sys/stat.h>
#include <pthread.h>
#include <thread>
#include <unistd.h>
#include "git_version.h"
#include <string>
#include <vector>
#include <csignal>
#include <cstdlib>
#include <iomanip>
#include <sstream>

#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/screen.hpp>
#include <ftxui/screen/terminal.hpp>
#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>

using namespace ftxui;

static const int MAX_PEERS_PER_NODE = 512;
static const int MAX_NODES = 32;
static const char* SHM_NAME = "/bitcoin_peer_scanner_shm";
static const char* STATE_FILE = "dry_run.state";

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
    float score_per_100;   // first responders per 100 blocks
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
    std::atomic<uint32_t> fidget;
    std::atomic<bool> dirty;
    int node_count;
    NodeState nodes[MAX_NODES];
    char config_error[128];
    char config_path[256];
};

static SharedState* shm = nullptr;

static int page = 0;          // 0 = all nodes, 1..N = single node
static int scroll_offset = 0;
static bool justify = true;
static int highlight = 0;
static std::string selected_addr;
static int selected_node = -1;
static bool show_history = false;
static std::string filter;
static bool filter_mode = false;
static int term_rows = 40;
static int sort_mode = 0;  // 0=score, 1=subver, 2=address
static const char* sort_names[] = {"score", "subver", "address"};
static int last_header_h = 5;
static std::vector<int> peer_body_lines;
static std::vector<int> peer_nodes;

static void restore_terminal() {
    // Disable mouse tracking modes that FTXUI enables
    std::cout << "\033[?1000l"   // disable mouse click tracking
              << "\033[?1002l"   // disable mouse button event tracking
              << "\033[?1003l"   // disable all motion tracking
              << "\033[?1006l"   // disable SGR mouse mode
              << "\033[?1015l"   // disable urxvt mouse mode
              << "\033[?25h"     // show cursor
              << "\033[0 q"      // reset cursor shape
              << "\033[?1049l"   // leave alternate screen
              << std::flush;
}

static void on_signal(int) {
    restore_terminal();
    std::_Exit(1);
}

static void save_dry_run() {
    if (!shm) return;
    std::ofstream f(STATE_FILE, std::ios::trunc);
    if (f) f << (shm->dry_run.load() ? 1 : 0) << "\n";
}

static Element flag_element(const char* label, bool supported, bool force_green) {
    bool green = supported || force_green;
    return text(std::string(label) + (green ? "+" : "-")) |
           color(green ? Color::Green : Color::Red);
}

static std::string pad_addr(const std::string& addr) {
    std::string s = addr;
    if (s.size() > 21) s = s.substr(0, 21);
    s.resize(22, ' ');
    return s;
}

static std::string pretty_json(const std::string& raw, int wrap = 36) {
    std::string out;
    int indent = 0;
    bool in_str = false;
    std::string line;
    auto flush = [&]() {
        if (!line.empty()) {
            out += std::string(indent, ' ') + line + '\n';
            line.clear();
        }
    };
    for (size_t i = 0; i < raw.size(); ++i) {
        char c = raw[i];
        if (c == '"' && (i == 0 || raw[i-1] != '\\')) in_str = !in_str;
        if (!in_str) {
            if (c == '{' || c == '[') {
                flush();
                out += std::string(indent, ' ') + c + '\n';
                indent++;
                continue;
            }
            if (c == '}' || c == ']') {
                flush();
                indent = std::max(0, indent - 1);
                out += std::string(indent, ' ') + c;
                if (i + 1 < raw.size() && raw[i+1] == ',') { out += ','; ++i; }
                out += '\n';
                continue;
            }
            if (c == ',') {
                line += c;
                flush();
                continue;
            }
            if (c == ':') { line += c; line += ' '; continue; }
            if (c == ' ' || c == '\n' || c == '\t' || c == '\r') continue;
        }
        line += c;
        if ((int)line.size() >= wrap - indent) flush();
    }
    flush();
    return out;
}

static Element render_ui() {
    if (!shm) return text("No shared memory") | color(Color::Red);
    shm->dirty.store(false);

    Elements header;
    Elements body;
    bool dry = shm->dry_run.load();
    bool mismatch = shm->parse_mismatch.load();

    static uint32_t last_fidget = 0;
    static auto last_change = std::chrono::steady_clock::now();
    uint32_t cur = shm->fidget.load();
    auto now = std::chrono::steady_clock::now();
    if (cur != last_fidget) {
        last_fidget = cur;
        last_change = now;
    }
    bool daemon_up = (now - last_change) < std::chrono::seconds(3);

    header.push_back(
        hbox({
            text("Bitcoin Peer Display " GIT_COMMIT_HASH) | bold,
            text("  |  "),
            text(dry ? "DRY-RUN" : "LIVE") | bold | color(dry ? Color::Yellow : Color::Red),
            text(mismatch ? "  [PARSE MISMATCH]" : "  [COUNT OK]") | bold | color(mismatch ? Color::Red : Color::Green),
            text(daemon_up ? "  [daemon OK]" : "  [daemon DOWN]") | color(daemon_up ? Color::Green : Color::Red),
            text("   [Ctrl+R] dry  [←→] page  [↑↓] select  [TAB] justify  [s] sort  [Ctrl+H] hist  [Ctrl+F] filter  [q] quit") | dim
        })
    );
    header.push_back(text("BLAKE2B → both green   |   RDTS → green   |   neither → red   |   score = first-responder / 100 blocks"));
    if (shm->config_error[0]) {
        header.push_back(text(std::string("CONFIG ERROR: ") + shm->config_error) | bold | color(Color::Red));
    }
    header.push_back(separator());

    pthread_mutex_lock(&shm->mutex);
    int nnodes = shm->node_count;
    if (nnodes < 1) nnodes = 0;
    if (page < 0) page = 0;
    if (page > nnodes) page = 0;

    std::string page_title = (page == 0) ? "ALL NODES" : shm->nodes[page - 1].name;
    Element filter_line = text("Page: " + page_title + "  filter: " + (filter.empty() ? "(none)" : filter) +
                               (justify ? "  justify:ON" : "  justify:OFF") +
                               "  sort:" + sort_names[sort_mode]);
    header.push_back(filter_mode ? (filter_line | color(Color::Yellow) | bold)
                                 : (filter_line | dim));
    if (show_history) header.push_back(text("[HISTORY MODE]") | bold | color(Color::Magenta));

    std::vector<const PeerInfo*> visible_peers;
    int selected_body_line = -1;
    peer_body_lines.clear();
    peer_nodes.clear();
    auto render_node = [&](int n) {
        const NodeState& st = shm->nodes[n];
        body.push_back(text(std::string("=== ") + st.name + " ===") | bold | color(Color::Cyan));
        if (st.last_error[0]) {
            body.push_back(text(std::string("  ") + st.last_error) | color(Color::Red));
            return;
        }
        body.push_back(text("  peers=" + std::to_string(st.peer_count) +
                            "  banned_this_scan=" + std::to_string(st.banned_count) +
                            "  blocks=" + std::to_string(st.blocks_height) +
                            "  headers=" + std::to_string(st.headers_height)));
        std::vector<const PeerInfo*> sorted;
        for (int i = 0; i < st.peer_count; ++i) sorted.push_back(&st.peers[i]);
        std::sort(sorted.begin(), sorted.end(), [](const PeerInfo* a, const PeerInfo* b) {
            if (a->is_inject != b->is_inject) return a->is_inject > b->is_inject;
            if (a->is_keep != b->is_keep) return a->is_keep > b->is_keep;
            if (sort_mode == 1) return std::string(a->subver) < std::string(b->subver);
            if (sort_mode == 2) return std::string(a->addr) < std::string(b->addr);
            return a->score_per_100 > b->score_per_100;
        });
        for (const PeerInfo* pp : sorted) {
            const PeerInfo& p = *pp;
            if (!filter.empty() && std::string(p.addr).find(filter) == std::string::npos &&
                std::string(p.ip).find(filter) == std::string::npos) continue;
            visible_peers.push_back(pp);
            peer_body_lines.push_back((int)body.size());
            peer_nodes.push_back(n);
            bool selected = (!selected_addr.empty() && std::string(p.addr) == selected_addr &&
                             (selected_node < 0 || selected_node == n)) ||
                            (selected_addr.empty() && (int)visible_peers.size() - 1 == highlight);
            if (selected) {
                highlight = (int)visible_peers.size() - 1;
                selected_node = n;
                selected_body_line = (int)body.size();
            }
            bool force_rdts = p.has_blake2b;
            std::string addr_disp = justify ? pad_addr(p.addr) : (std::string(p.addr) + "  ");
            Elements row = {
                text((selected ? "> " : "  ") + addr_disp),
                flag_element("BLAKE2B", p.has_blake2b, false),
                text(" "),
                flag_element("RDTS", p.has_rdts, force_rdts),
                text(" "),
                text(std::string(p.subver).substr(0, 16)) | dim,
            };
            if (p.is_inject) row.push_back(text(" [INJECT]") | color(Color::Cyan));
            else if (p.is_keep) row.push_back(text(" [KEEP]") | color(Color::Yellow));
            if (p.banned) row.push_back(text(" [BANNED]") | color(Color::Red) | bold);
            char scorebuf[48];
            snprintf(scorebuf, sizeof(scorebuf), "  score=%.1f  conn=%us  fr=%u",
                     p.score_per_100, p.connected_seconds, p.first_responder_count);
            row.push_back(text(scorebuf) | dim);
            Element line = hbox(std::move(row));
            if (selected) line = line | inverted;
            body.push_back(line);
        }
        body.push_back(text(""));
    };

    if (show_history) {
        body.push_back(text("=== HISTORY (peers.db) ===") | bold | color(Color::Magenta));
        std::ifstream db("peers.db");
        if (db) {
            std::string line;
            int shown = 0;
            while (std::getline(db, line) && shown < 200) {
                if (line.empty() || line[0] == '#') continue;
                if (!filter.empty() && line.find(filter) == std::string::npos) continue;
                body.push_back(text("  " + line) | dim);
                shown++;
            }
            if (shown == 0) body.push_back(text("  (no matching history)") | dim);
        } else {
            body.push_back(text("  (peers.db not found)") | color(Color::Red));
        }
    } else if (page == 0) {
        for (int n = 0; n < nnodes && n < MAX_NODES; ++n) render_node(n);
    } else if (page >= 1 && page <= nnodes) {
        render_node(page - 1);
    }
    pthread_mutex_unlock(&shm->mutex);

    if (highlight >= (int)visible_peers.size()) highlight = std::max(0, (int)visible_peers.size() - 1);
    if (highlight >= 0 && highlight < (int)visible_peers.size()) {
        selected_addr = visible_peers[highlight]->addr;
        if (highlight < (int)peer_nodes.size()) selected_node = peer_nodes[highlight];
    }

    int header_h = (int)header.size();
    last_header_h = header_h;
    int body_view = std::max(5, term_rows - header_h - 4);
    if (selected_body_line >= 0) {
        if (selected_body_line < scroll_offset)
            scroll_offset = selected_body_line;
        else if (selected_body_line >= scroll_offset + body_view)
            scroll_offset = selected_body_line - body_view + 1;
    }
    int max_scroll = std::max(0, (int)body.size() - body_view + 2);
    if (scroll_offset > max_scroll) scroll_offset = max_scroll;
    if (scroll_offset < 0) scroll_offset = 0;

    Elements body_vis;
    for (int i = scroll_offset; i < (int)body.size() && (int)body_vis.size() < body_view; ++i)
        body_vis.push_back(body[i]);
    if (body_vis.empty()) body_vis.push_back(text("(empty)"));

    Elements right;
    if (!visible_peers.empty() && highlight >= 0 && highlight < (int)visible_peers.size()) {
        const PeerInfo& sel = *visible_peers[highlight];
        right.push_back(text("SELECTED PEER") | bold | color(Color::Yellow));
        right.push_back(text(std::string("addr: ") + sel.addr));
        right.push_back(text(std::string("ip:   ") + sel.ip));
        right.push_back(text(std::string("BLAKE2B: ") + (sel.has_blake2b ? "yes" : "no")));
        right.push_back(text(std::string("RDTS:    ") + (sel.has_rdts ? "yes" : "no")));
        right.push_back(text("first_resp: " + std::to_string(sel.first_responder_count)));
        right.push_back(text("connected:  " + std::to_string(sel.connected_seconds) + "s"));
        char sb[32]; snprintf(sb, sizeof(sb), "score/100:  %.2f", sel.score_per_100);
        right.push_back(text(sb));
        right.push_back(separator());
        std::string safe = sel.addr[0] ? sel.addr : sel.ip;
        for (char& ch : safe) if (ch == ':' || ch == '/' || ch == '\\' || ch == '[' || ch == ']') ch = '_';
        std::ifstream jf(std::string("peer_json_") + safe + ".txt");
        if (jf) {
            std::stringstream ss; ss << jf.rdbuf();
            std::string pretty = pretty_json(ss.str(), 36);
            std::istringstream ls(pretty);
            std::string ln;
            while (std::getline(ls, ln)) right.push_back(text(ln) | dim);
        } else {
            right.push_back(text("(JSON not yet written)") | dim);
        }
    } else {
        right.push_back(text("No peer selected") | dim);
    }

    Elements left;
    left.insert(left.end(), header.begin(), header.end());
    left.insert(left.end(), body_vis.begin(), body_vis.end());

    return hbox({
        vbox(std::move(left)) | flex | border,
        vbox(std::move(right)) | size(WIDTH, EQUAL, 40) | border
    });
}

int main() {
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    int fd = shm_open(SHM_NAME, O_RDWR, 0666);
    if (fd < 0) {
        std::cerr << "Cannot open shared memory. Is peer_daemon running?\n";
        return 1;
    }
    shm = (SharedState*)mmap(nullptr, sizeof(SharedState), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (shm == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    auto screen = ScreenInteractive::Fullscreen();
    auto component = Renderer([&] {
        auto sz = Terminal::Size();
        if (sz.dimy > 0) term_rows = sz.dimy;
        return render_ui();
    });

    std::atomic<bool> display_running{true};
    std::thread refresher([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        // disable any-motion tracking, keep click + wheel
        std::cout << "\033[?1003l\033[?1000h\033[?1006h" << std::flush;
        while (display_running.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (shm && shm->dirty.load())
                screen.PostEvent(Event::Custom);
        }
    });

    component |= CatchEvent([&](Event event) {
        if (event == Event::Character('q') || event == Event::Character('Q')) {
            display_running.store(false);
            screen.ExitLoopClosure()();
            return true;
        }
        if (event == Event::Special("\x12") ||
            (event.is_character() && event.character() == "\x12")) {
            if (shm) {
                shm->dry_run.store(!shm->dry_run.load());
                save_dry_run();
            }
            return true;
        }
        if (event == Event::ArrowUp) {
            highlight = std::max(0, highlight - 1);
            selected_addr.clear();
            selected_node = -1;
            return true;
        }
        if (event == Event::ArrowDown) {
            highlight++;
            selected_addr.clear();
            selected_node = -1;
            return true;
        }
        if (event == Event::PageUp) {
            int step = std::max(1, term_rows - 8);
            highlight = std::max(0, highlight - step);
            selected_addr.clear();
            selected_node = -1;
            return true;
        }
        if (event == Event::PageDown) {
            int step = std::max(1, term_rows - 8);
            highlight += step;
            selected_addr.clear();
            selected_node = -1;
            return true;
        }
        if (event == Event::Home) {
            highlight = 0;
            scroll_offset = 0;
            selected_addr.clear();
            selected_node = -1;
            return true;
        }
        if (event == Event::End) {
            highlight = 100000;
            selected_addr.clear();
            selected_node = -1;
            return true;
        }
        if (event == Event::Special("\x08") || event == Event::Character('\x08')) { // Ctrl+H
            if (filter_mode) {
                if (!filter.empty()) filter.pop_back();
            } else {
                show_history = !show_history;
            }
            return true;
        }
        if (event == Event::Special("\x06") || event == Event::Character('\x06')) { // Ctrl+F
            filter_mode = !filter_mode;
            if (!filter_mode) filter.clear();
            return true;
        }
        if (filter_mode) {
            if (event == Event::Backspace || event == Event::Delete ||
                event == Event::Character('\x7f') || event == Event::Character('\b') ||
                (event.is_character() && (event.character() == "\x7f" || event.character() == "\b"))) {
                if (!filter.empty()) filter.pop_back();
                return true;
            }
            if (event.is_character() && event.character().size() == 1 && event.character()[0] >= 32) {
                filter += event.character();
                return true;
            }
        }
        if (event == Event::ArrowLeft) {
            pthread_mutex_lock(&shm->mutex);
            int n = shm->node_count;
            pthread_mutex_unlock(&shm->mutex);
            page = (page - 1 + n + 1) % (n + 1);
            scroll_offset = 0;
            return true;
        }
        if (event == Event::ArrowRight) {
            pthread_mutex_lock(&shm->mutex);
            int n = shm->node_count;
            pthread_mutex_unlock(&shm->mutex);
            page = (page + 1) % (n + 1);
            scroll_offset = 0;
            return true;
        }
        if (event == Event::Character('s') || event == Event::Character('S')) {
            sort_mode = (sort_mode + 1) % 3;
            return true;
        }
        if (event == Event::Tab) {
            justify = !justify;
            return true;
        }
        if (event.is_mouse()) {
            auto& m = event.mouse();
            // drop pure motion (no button) immediately
            if (m.button == Mouse::None) return true;
            if (m.button == Mouse::WheelUp) {
                scroll_offset = std::max(0, scroll_offset - 3);
                return true;
            }
            if (m.button == Mouse::WheelDown) {
                scroll_offset += 3;
                return true;
            }
            if (m.button == Mouse::Left && m.motion == Mouse::Pressed) {
                int body_line = scroll_offset + (m.y - last_header_h - 1);
                // find the peer whose body line is closest to the click
                int best = -1, best_dist = 999;
                for (int i = 0; i < (int)peer_body_lines.size(); ++i) {
                    int d = std::abs(peer_body_lines[i] - body_line);
                    if (d < best_dist) { best_dist = d; best = i; }
                }
                if (best >= 0 && best_dist <= 1) {
                    highlight = best;
                    selected_addr.clear();
                    selected_node = -1;
                    return true;
                }
            }
        }
        return false;
    });

    screen.Loop(component);
    display_running.store(false);
    if (refresher.joinable()) refresher.join();

    restore_terminal();
    munmap(shm, sizeof(SharedState));
    return 0;
}
