#include <bits/stdc++.h>
using namespace std;

static int quantum_select(const vector<double>& scores, double temp) {
    if (scores.empty()) return 0;
    double mx = *max_element(scores.begin(), scores.end());
    vector<double> w(scores.size());
    double Z = 0.0;
    double T = max(1e-6, temp);
    for (size_t i = 0; i < scores.size(); ++i) {
        double v = (scores[i] - mx) / T;
        double e = exp(min(700.0, max(-700.0, v))); // clamp to avoid inf
        w[i] = e;
        Z += e;
    }
    if (Z <= 0) return 0;
    double r = (double)rand() / RAND_MAX;
    double acc = 0.0;
    for (size_t i = 0; i < w.size(); ++i) {
        acc += w[i] / Z;
        if (r <= acc) return (int)i;
    }
    return (int)w.size() - 1;
}

static uint64_t hash_str(const string& s) {
    // FNV-1a 64-bit
    uint64_t h = 1469598103934665603ULL;
    for (unsigned char c : s) {
        h ^= c;
        h *= 1099511628211ULL;
    }
    return h;
}

struct LFSR { int width; int a; int b; uint64_t state; };

static LFSR build_lfsr(const vector<string>& tokens) {
    uint64_t seed = 0;
    for (auto &t : tokens) seed ^= (hash_str(t) & 0xFFFF);
    int width = max(4, min(16, (int)tokens.size() % 12 + 4));
    int a = (int)(seed % (width - 1)) + 1;
    int b = (int)((seed >> 3) % (width - 1)) + 1;
    if (a == b) b = (b % (width - 1)) + 1;
    uint64_t st = (seed ? seed : 1) & ((1u << width) - 1);
    return {width, a, b, st};
}

static int lfsr_step(LFSR &c, int inp_bit = 1) {
    int bit_a = (c.state >> (c.a - 1)) & 1;
    int bit_b = (c.state >> (c.b - 1)) & 1;
    int fb = bit_a ^ bit_b ^ (inp_bit & 1);
    c.state = ((c.state << 1) | (uint64_t)fb) & ((1u << c.width) - 1);
    return (int)(c.state & 1u);
}

static void cmd_hdl(int argc, char** argv) {
    if (argc < 3) {
        cout << "{\"error\":\"usage: hdl <steps> <tokens...>\"}\n";
        return;
    }
    int steps = stoi(argv[2]);
    vector<string> tokens;
    for (int i = 3; i < argc; ++i) tokens.emplace_back(argv[i]);
    auto c = build_lfsr(tokens);
    int ones = 0, toggles = 0;
    int last = (int)(c.state & 1u);
    for (int i = 0; i < steps; ++i) {
        int o = lfsr_step(c, 1);
        ones += o;
        if (o != last) toggles++;
        last = o;
    }
    double bias = steps ? (double)ones / (double)steps : 0.0;
    double stability = steps ? 1.0 - (double)toggles / (double)steps : 1.0;
    cout.setf(std::ios::fixed); cout<<setprecision(6);
    cout << "{\"bias\":" << bias << ",\"stability\":" << stability << "}\n";
}

static void cmd_quantum_select(int argc, char** argv) {
    if (argc < 4) {
        cout << "{\"error\":\"usage: quantum_select <temperature> <scores...>\"}\n";
        return;
    }
    double T = atof(argv[2]);
    vector<double> scores;
    for (int i = 3; i < argc; ++i) scores.push_back(atof(argv[i]));
    int idx = quantum_select(scores, T);
    cout << "{\"index\":" << idx << "}\n";
}

static void cmd_phre(int argc, char** argv) {
    if (argc < 5) {
        cout << "{\"error\":\"usage: phre <steps> <seed> <axiom_lengths...>\"}\n";
        return;
    }
    int steps = stoi(argv[2]);
    int seed = stoi(argv[3]);
    vector<int> lens;
    for (int i = 4; i < argc; ++i) lens.push_back(max(1, stoi(argv[i])));
    std::mt19937 rng((uint32_t)seed);
    double score = 0.0;
    for (int s = 0; s < steps; ++s) {
        int L = lens[s % (int)lens.size()];
        score += max(0.0, 1.0 / (1.0 + (double)L)) * (1.0 + 0.01 * s);
        if (std::uniform_real_distribution<>(0.0,1.0)(rng) < 0.01) {
            score *= 1.05;
        }
    }
    cout.setf(std::ios::fixed); cout<<setprecision(6);
    cout << "{\"score\":" << score << "}\n";
}

int main(int argc, char** argv) {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    if (argc < 2) {
        cout << "{\"error\":\"usage: <command> ...; commands: hdl, quantum_select, phre\"}\n";
        return 0;
    }
    string cmd = argv[1];
    if (cmd == "hdl") cmd_hdl(argc, argv);
    else if (cmd == "quantum_select") cmd_quantum_select(argc, argv);
    else if (cmd == "phre") cmd_phre(argc, argv);
    else cout << "{\"error\":\"unknown command\"}\n";
    return 0;
}
