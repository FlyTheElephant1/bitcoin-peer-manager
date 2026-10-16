// peer_display.cpp
// Separate live display. Attaches to shared memory created by peer_daemon.
// Ctrl+R toggles dry-run (writes atomic + file).
//
// Build: g++ -std=c++17 -pthread -O2 -o peer_display peer_display.cpp -lrt \
//        $(pkg-config --cflags --libs ftxui)   # or link ftxui libs

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

#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/screen.hpp>
#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>

using namespace ftxui;

// Must match daemon
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

static Element render_ui() {
    if (!shm) return text("No shared memory") | color(Color::Red);

    Elements content;
    bool dry = shm->dry_run.load();
    bool mismatch = shm->parse_mismatch.load();

    // Heartbeat: fidget must change at least once every ~2s
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
            text("   [Ctrl+R] toggle   [q] quit") | dim
        })
    );
    content.push_back(text("BLAKE2B → both green   |   RDTS → green   |   neither → red"));
    if (shm->config_error[0]) {
        content.push_back(text(std::string("CONFIG ERROR: ") + shm->config_error) | bold | color(Color::Red));
    }
    content.push_back(separator());

    pthread_mutex_lock(&shm->mutex);
    int nnodes = shm->node_count;
    for (int n = 0; n < nnodes && n < MAX_NODES; ++n) {
        const NodeState& st = shm->nodes[n];
        content.push_back(text(std::string("=== ") + st.name + " ===") | bold | color(Color::Cyan));

        if (st.last_error[0]) {
            content.push_back(text(std::string("  ") + st.last_error) | color(Color::Red));
            continue;
        }

        content.push_back(text("  peers=" + std::to_string(st.peer_count) +
                               "  banned_this_scan=" + std::to_string(st.banned_count)));

        for (int i = 0; i < st.peer_count; ++i) {
            const PeerInfo& p = st.peers[i];
            bool force_rdts = p.has_blake2b;
            Elements row = {
                text(std::string("  ") + p.addr + "  "),
                flag_element("BLAKE2B", p.has_blake2b, false),
                text(" "),
                flag_element("RDTS", p.has_rdts, force_rdts),
            };
            if (p.banned) row.push_back(text(" [BANNED]") | color(Color::Red) | bold);
            // KEEP marker would need the keep_ip in shared mem; omitted for simplicity
            content.push_back(hbox(std::move(row)));
        }
        content.push_back(text(""));
    }
    pthread_mutex_unlock(&shm->mutex);

    return vbox(std::move(content)) | border;
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

    // Force periodic refresh even when the terminal is inactive (SSH focus issues)
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
        return false;
    });

    screen.Loop(component);
    display_running.store(false);
    if (refresher.joinable()) refresher.join();

    // Restore terminal cursor and modes (avoids leftover block cursor over SSH)
    std::cout << "\033[?25h"   // show cursor
              << "\033[0 q"    // reset cursor shape to default
              << "\033[?1049l" // exit alternate screen if still active
              << std::flush;

    munmap(shm, sizeof(SharedState));
    return 0;
}
