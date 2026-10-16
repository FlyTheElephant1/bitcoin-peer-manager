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
#include <string>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <sstream>

#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/screen.hpp>
#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>

using namespace ftxui;

static const int MAX_PEERS_PER_NODE = 128;
static const int MAX_NODES = 32;
static const char* SHM_NAME = "/bitcoin_peer_scanner_shm";
static const char* STATE_FILE = "dry_run.state";

struct PeerInfo {
    char addr[64];
    char ip[46];
    bool has_blake2b;
    bool has_rdts;
    bool banned;
    bool is_keep;
    bool is_inject;
    uint32_t first_responder_count;
    uint32_t connected_seconds;
    float score_per_100;   // first responders per 100 blocks
};

struct NodeState {
    char name[32];
    PeerInfo peers[MAX_PEERS_PER_NODE];
    int peer_count;
    int banned_count;
    char last_error[64];
};

struct SharedState {
    pthread_mutex_t mutex;
    std::atomic<bool> dry_run;
    std::atomic<bool> parse_mismatch;
    std::atomic<bool> daemon_running;
    std::atomic<uint32_t> fidget;
    int node_count;
    NodeState nodes[MAX_NODES];
    char config_error[128];
    char config_path[256];
};

static SharedState* shm = nullptr;

static int page = 0;          // 0 = all nodes, 1..N = single node
static int scroll_offset = 0;
static bool justify = true;
static int highlight = 0;     // index in the currently visible peer list
static bool show_history = false;
static std::string filter;    // live filter term
static bool filter_mode = false;

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
    s.resize(22, ' ');  // 22nd always blank
    return s;
}

static Element render_ui() {
    if (!shm) return text("No shared memory") | color(Color::Red);

    Elements content;
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

    content.push_back(
        hbox({
            text("Bitcoin Peer Display") | bold,
            text("  |  "),
            text(dry ? "DRY-RUN" : "LIVE") | bold | color(dry ? Color::Yellow : Color::Red),
            text(mismatch ? "  [PARSE MISMATCH]" : "  [COUNT OK]") | bold | color(mismatch ? Color::Red : Color::Green),
            text(daemon_up ? "  [daemon OK]" : "  [daemon DOWN]") | color(daemon_up ? Color::Green : Color::Red),
            text("   [Ctrl+R] dry  [←→] page  [↑↓] select  [TAB] justify  [Ctrl+H] hist  [Ctrl+F] filter  [q] quit") | dim
        })
    );
    content.push_back(text("BLAKE2B → both green   |   RDTS → green   |   neither → red   |   score = first-responder / 100 blocks"));
    if (shm->config_error[0]) {
        content.push_back(text(std::string("CONFIG ERROR: ") + shm->config_error) | bold | color(Color::Red));
    }
    content.push_back(separator());

    pthread_mutex_lock(&shm->mutex);
    int nnodes = shm->node_count;
    if (nnodes < 1) nnodes = 0;

    // Clamp page
    if (page < 0) page = 0;
    if (page > nnodes) page = 0;

    std::string page_title = (page == 0) ? "ALL NODES" : shm->nodes[page - 1].name;
    content.push_back(text("Page: " + page_title +
                           (filter_mode ? "  FILTER: " + filter : "") +
                           (show_history ? "  [HISTORY]" : "") +
                           "  (justify " + (justify ? "ON" : "OFF") + ")") | dim);

    std::vector<const PeerInfo*> visible_peers;
    auto render_node = [&](int n) {
        const NodeState& st = shm->nodes[n];
        content.push_back(text(std::string("=== ") + st.name + " ===") | bold | color(Color::Cyan));

        if (st.last_error[0]) {
            content.push_back(text(std::string("  ") + st.last_error) | color(Color::Red));
            return;
        }

        content.push_back(text("  peers=" + std::to_string(st.peer_count) +
                               "  banned_this_scan=" + std::to_string(st.banned_count)));

        std::vector<const PeerInfo*> sorted;
        for (int i = 0; i < st.peer_count; ++i) sorted.push_back(&st.peers[i]);
        std::stable_sort(sorted.begin(), sorted.end(), [](const PeerInfo* a, const PeerInfo* b) {
            if (a->is_inject != b->is_inject) return a->is_inject > b->is_inject;
            if (a->is_keep != b->is_keep) return a->is_keep > b->is_keep;
            return a->score_per_100 > b->score_per_100;
        });

        for (const PeerInfo* pp : sorted) {
            const PeerInfo& p = *pp;
            if (!filter.empty() && std::string(p.addr).find(filter) == std::string::npos &&
                std::string(p.ip).find(filter) == std::string::npos) continue;
            visible_peers.push_back(pp);
            bool selected = ((int)visible_peers.size() - 1 == highlight);
            bool force_rdts = p.has_blake2b;
            std::string addr_disp = justify ? pad_addr(p.addr) : (std::string(p.addr) + "  ");
            Elements row = {
                text((selected ? "> " : "  ") + addr_disp),
                flag_element("BLAKE2B", p.has_blake2b, false),
                text(" "),
                flag_element("RDTS", p.has_rdts, force_rdts),
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
            content.push_back(line);
        }
        content.push_back(text(""));
    };

    if (show_history && page > 0) {
        content.push_back(text("=== HISTORY (from peers.db) ===") | bold | color(Color::Magenta));
        content.push_back(text("  (full history written to peers.db every 60s)"));
        content.push_back(text("  Select a live peer to see its tracked stats on the right."));
    } else if (page == 0) {
        for (int n = 0; n < nnodes && n < MAX_NODES; ++n) render_node(n);
    } else if (page >= 1 && page <= nnodes) {
        render_node(page - 1);
    }
    pthread_mutex_unlock(&shm->mutex);

    if (highlight >= (int)visible_peers.size()) highlight = std::max(0, (int)visible_peers.size() - 1);

    Elements left = content;
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
        right.push_back(text("(full JSON in peers.db)") | dim);
    } else {
        right.push_back(text("No peer selected") | dim);
    }

    // Apply scroll to left
    Elements left_vis;
    int start = std::max(0, scroll_offset);
    for (size_t i = start; i < left.size(); ++i) left_vis.push_back(left[i]);
    if (left_vis.empty()) left_vis.push_back(text("(empty)"));

    return hbox({
        vbox(std::move(left_vis)) | flex | border,
        vbox(std::move(right)) | size(WIDTH, EQUAL, 40) | border
    });
}

int main() {
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
    auto component = Renderer([&] { return render_ui(); });

    std::atomic<bool> display_running{true};
    std::thread refresher([&] {
        while (display_running.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
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
            return true;
        }
        if (event == Event::ArrowDown) {
            highlight++;
            return true;
        }
        if (event == Event::Special("\x08") || event == Event::Character('\x08')) { // Ctrl+H
            show_history = !show_history;
            return true;
        }
        if (event == Event::Special("\x06") || event == Event::Character('\x06')) { // Ctrl+F
            filter_mode = !filter_mode;
            if (!filter_mode) filter.clear();
            return true;
        }
        if (filter_mode && event.is_character()) {
            if (event == Event::Backspace && !filter.empty()) filter.pop_back();
            else if (event.character().size() == 1 && event.character()[0] >= 32)
                filter += event.character();
            return true;
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
        if (event == Event::Tab) {
            justify = !justify;
            return true;
        }
        if (event.is_mouse()) {
            auto& m = event.mouse();
            if (m.button == Mouse::WheelUp) {
                scroll_offset = std::max(0, scroll_offset - 3);
                return true;
            }
            if (m.button == Mouse::WheelDown) {
                scroll_offset += 3;
                return true;
            }
        }
        return false;
    });

    screen.Loop(component);
    display_running.store(false);
    if (refresher.joinable()) refresher.join();

    std::cout << "\033[?25h\033[0 q\033[?1049l" << std::flush;
    munmap(shm, sizeof(SharedState));
    return 0;
}
