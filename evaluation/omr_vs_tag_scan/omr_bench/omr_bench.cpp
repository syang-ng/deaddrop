// omr_bench.cpp: role-split benchmark harness for the DeadDrop OMR detection path (experiment E2).
//
// It calls the existing functions in omr-server/include (API.h, OMRdos.h, serialize.h) without
// changing them. Each role runs as its own process, so CPU time and peak memory are measured per
// role, and every protocol message is written to a file whose size is its serialized length:
//
//   omr_bench receiver-keygen KEYDIR            receiver: keys; writes sk_decode, pk_clue,
//                                               pk_detect, relin and Galois keys (seeded form)
//   omr_bench build-board N INDEX PK_CLUE       board: N dummy clues as init_deaddrop() makes them,
//                                               then one sender clue to the receiver at INDEX
//   omr_bench detect KEYDIR DIGEST_OUT          detector: loads the receiver's keys (setup), then
//                                               runs gen_encrypted_digest() once (one poll)
//   omr_bench decode KEYDIR DIGEST              receiver: decrypts the digest, recovers indices
//   omr_bench export-board N OUT                board: writes all N clues in the clue wire format
//   omr_bench local-scan KEYDIR BOARD [THREADS] receiver, no detector: tests every downloaded clue
//                                               with the srPKE key, using the detector's predicate
//
// The board and detector read and write clues at ../data/clues/ relative to the working
// directory, as the prototype does. Each command prints one line starting with "RESULT ".

#include "include/OMRUtil.h"
#include "include/GOMR.h"
#include "include/OMR.h"
#include "include/OMRopt.h"
#include "include/OMRdos.h"
#include "include/MRE.h"
#include "include/API.h"
#include "include/serialize.h"

#include <seal/seal.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using namespace std;
using namespace seal;

namespace bench {

struct Usage {
    double cpu_s;
    long maxrss_kb;
};

Usage usage_now() {
    rusage ru{};
    if (getrusage(RUSAGE_SELF, &ru) != 0)
        throw runtime_error("getrusage failed");
    auto tv = [](const timeval &t) { return double(t.tv_sec) + double(t.tv_usec) * 1e-6; };
    return {tv(ru.ru_utime) + tv(ru.ru_stime), ru.ru_maxrss};
}

// Wall clock and process CPU time (all threads) since construction.
struct Timer {
    chrono::steady_clock::time_point t0 = chrono::steady_clock::now();
    double cpu0 = usage_now().cpu_s;
    double wall() const { return chrono::duration<double>(chrono::steady_clock::now() - t0).count(); }
    double cpu() const { return usage_now().cpu_s - cpu0; }
};

// Same BFV parameters as init_deaddrop() in omr-server/include/API.h.
SEALContext make_context() {
    size_t poly_modulus_degree = 32768;
    int t = 65537;
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {40, 60, 60, 60, 60,
                                                                       60, 60, 60, 60,
                                                                       60, 60, 60, 60,
                                                                       60, 60, 30, 60}));
    parms.set_plain_modulus(t);
    return SEALContext(parms, true, sec_level_type::none);
}

void write_file(const string &path, const string &bytes) {
    ofstream f(path, ios::binary | ios::trunc);
    if (!f)
        throw runtime_error("cannot open " + path + " for writing");
    f.write(bytes.data(), static_cast<streamsize>(bytes.size()));
    f.close();
    if (f.fail())
        throw runtime_error("write to " + path + " failed");
}

string read_file(const string &path) {
    ifstream f(path, ios::binary);
    if (!f)
        throw runtime_error("cannot open " + path);
    ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

long long file_size(const string &path) {
    struct stat st {};
    if (stat(path.c_str(), &st) != 0)
        throw runtime_error("cannot stat " + path);
    return static_cast<long long>(st.st_size);
}

template <class T>
string save_serializable(const seal::Serializable<T> &obj) {
    ostringstream ss;
    obj.save(ss, compr_mode_type::none);
    return ss.str();
}

template <class K>
K load_key(const SEALContext &context, const string &path) {
    ifstream f(path, ios::binary);
    if (!f)
        throw runtime_error("cannot open " + path);
    K key;
    key.load(context, f);  // validates the key against the context
    return key;
}

// Same decoding as digest_to_indices() in deadbug/rust_omr/src/http_client.rs: slot s holds
// sum_b 2^b * PV[b * D + s] mod t, so bit b of slot s flags message b * D + s.
vector<uint64_t> digest_to_indices(const vector<uint64_t> &digest) {
    const uint64_t max_blocks = 16;
    const uint64_t slots = digest.size();
    vector<uint64_t> out;
    for (uint64_t s = 0; s < slots; ++s) {
        const uint64_t v = digest[s];
        if ((v >> max_blocks) != 0)
            throw runtime_error("digest slot " + to_string(s) + " holds " + to_string(v) +
                                ", not a bitmask of at most 16 blocks");
        for (uint64_t b = 0; b < max_blocks; ++b)
            if ((v >> b) & 1)
                out.push_back(b * slots + s);
    }
    sort(out.begin(), out.end());
    return out;
}

string join(const vector<uint64_t> &v) {
    ostringstream ss;
    for (size_t i = 0; i < v.size(); ++i)
        ss << (i ? "," : "") << v[i];
    return ss.str();
}

// srPKE secret key (ell vectors of length n1), in the same LE64 vector encoding serialize.h uses.
string serialize_srpke_sk(const srPKEsk &sk) {
    string out;
    append_u32(out, static_cast<uint32_t>(sk.size()));
    for (const auto &v : sk)
        out.append(SerializeNativeVectorLE64(v));
    return out;
}

srPKEsk deserialize_srpke_sk(const string &bytes, const NativeInteger &q) {
    string_view buf(bytes);
    size_t off = 0;
    srPKEsk sk(read_u32(buf, off));
    for (auto &v : sk)
        v = DeserializeNativeVectorLE64(buf, off, q);
    if (off != buf.size())
        throw runtime_error("sk_clue: trailing bytes");
    return sk;
}

// The detector's pertinency test, evaluated in the clear with the receiver's srPKE key.
// computeBplusAS_dos() forms x_l = (b_l - q/4) - <a, s_l> and rangeCheck_dos() accepts the clue
// when every |x_l| <= range_check_r_dos - 1. Arithmetic is exact (no unsigned wrap).
bool clue_is_pertinent(const srPKECiphertext &ct, const vector<vector<uint64_t>> &s, const srPKEParam &p) {
    const uint64_t q = p.q, q4 = p.q / 4;
    const int64_t bound = range_check_r_dos - 1;
    for (int l = 0; l < p.ell; l++) {
        uint64_t inner = 0;  // < 936 * 2^34, no overflow
        for (int i = 0; i < p.n1; i++)
            inner += ct.a[i].ConvertToInt() * s[l][i];
        inner %= q;
        const uint64_t x = (ct.b[l].ConvertToInt() + 2 * q - q4 - inner) % q;
        const int64_t xc = x > q / 2 ? int64_t(x) - int64_t(q) : int64_t(x);
        if (xc > bound || xc < -bound)
            return false;
    }
    return true;
}

int receiver_keygen(const string &dir) {
    Timer total;

    // Clue key pair, as init_deaddrop() lines "Generate first PKE pair".
    Timer t_clue;
    auto params = srPKEParam();
    auto sk = srPKEGenerateSecretKey(params);
    auto pk_clue = srPKEGeneratePublicKey(params, sk);
    const double clue_wall = t_clue.wall(), clue_cpu = t_clue.cpu();

    Timer t_ctx;
    SEALContext context = make_context();
    const double ctx_wall = t_ctx.wall(), ctx_cpu = t_ctx.cpu();

    // BFV keys and the detector's evaluation keys from the same key generator, as init_deaddrop().
    // The evaluation keys are made in SEAL's seeded (serializable) form, the form a receiver sends.
    Timer t_seal;
    KeyGenerator keygen(context);
    SecretKey sk_decode = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    seal::Serializable<RelinKeys> relin = keygen.create_relin_keys();
    vector<int> stepsfirst = {1};
    seal::Serializable<GaloisKeys> gal = keygen.create_galois_keys(stepsfirst);
    const double seal_wall = t_seal.wall(), seal_cpu = t_seal.cpu();

    Timer t_det;
    vector<Ciphertext> pk_detect = omr_dos::generateDetectionKey(context, 32768, public_key, sk_decode, sk, params);
    const double det_wall = t_det.wall(), det_cpu = t_det.cpu();

    const double keygen_wall = total.wall(), keygen_cpu = total.cpu();

    Timer t_ser;
    const string sk_bytes = SerializeSecretKeyDecode(sk_decode);
    const string pkc_bytes = SerializePublicKeyClue(pk_clue);
    const string pkd_bytes = SerializePublicKeyDetect(pk_detect);
    const string relin_bytes = save_serializable(relin);
    const string gal_bytes = save_serializable(gal);
    write_file(dir + "/sk_decode.bin", sk_bytes);
    write_file(dir + "/pk_clue.bin", pkc_bytes);
    write_file(dir + "/pk_detect.bin", pkd_bytes);
    write_file(dir + "/relin_keys.bin", relin_bytes);
    write_file(dir + "/galois_keys.bin", gal_bytes);
    // srPKE secret key: never sent anywhere; only the local clue scan (experiment 2) reads it.
    const string sk_clue_bytes = serialize_srpke_sk(sk);
    write_file(dir + "/sk_clue.bin", sk_clue_bytes);
    const double ser_wall = t_ser.wall();

    cout << fixed << setprecision(6) << "RESULT {\"tool\":\"omr\",\"phase\":\"receiver_keygen\""
         << ",\"wall_s\":" << keygen_wall << ",\"cpu_s\":" << keygen_cpu
         << ",\"clue_keys_wall_s\":" << clue_wall << ",\"clue_keys_cpu_s\":" << clue_cpu
         << ",\"context_wall_s\":" << ctx_wall << ",\"context_cpu_s\":" << ctx_cpu
         << ",\"bfv_and_eval_keys_wall_s\":" << seal_wall << ",\"bfv_and_eval_keys_cpu_s\":" << seal_cpu
         << ",\"detection_key_wall_s\":" << det_wall << ",\"detection_key_cpu_s\":" << det_cpu
         << ",\"serialize_wall_s\":" << ser_wall << ",\"maxrss_kb\":" << usage_now().maxrss_kb
         << ",\"sk_decode_bytes\":" << sk_bytes.size() << ",\"pk_clue_bytes\":" << pkc_bytes.size()
         << ",\"pk_detect_bytes\":" << pkd_bytes.size() << ",\"relin_keys_bytes\":" << relin_bytes.size()
         << ",\"galois_keys_bytes\":" << gal_bytes.size() << ",\"sk_clue_bytes\":" << sk_clue_bytes.size()
         << "}" << endl;
    return 0;
}

int build_board(int n, int index, const string &pk_clue_path) {
    if (n != ddctx::num_transactions)
        throw runtime_error("this binary was built for N = " + to_string(ddctx::num_transactions) +
                            ", not " + to_string(n));
    auto params = srPKEParam();
    srPKEpk pk_clue = DeserializePublicKeyClue(read_file(pk_clue_path), params.q);

    // N dummy clues, each under a fresh srPKE secret key, exactly as init_deaddrop() builds the
    // clue DB (num_of_pertinent_msgs = 0). The secret-key argument is not used for dummies.
    Timer t_board;
    auto sk_unused = srPKEGenerateSecretKey(params);
    vector<int> pertinentMsgIndices;
    preparingTransactionsFormal_dos(pertinentMsgIndices, sk_unused, pk_clue, n, 0, params, 1);
    const double board_wall = t_board.wall(), board_cpu = t_board.cpu();

    // Sender: one clue for the receiver, stored at INDEX (what /gen_clue and /submit_clue do).
    Timer t_send;
    srPKECiphertext clue = gen_clue(pk_clue);
    const double send_wall = t_send.wall(), send_cpu = t_send.cpu();
    const string clue_bytes = SerializeClue(clue);
    if (!submit_clue(clue, index))
        throw runtime_error("submit_clue failed for index " + to_string(index));
    const long long clue_file = file_size("../data/clues/" + to_string(index) + ".txt");

    cout << fixed << setprecision(6) << "RESULT {\"tool\":\"omr\",\"phase\":\"build_board\",\"n\":" << n
         << ",\"index\":" << index << ",\"board_wall_s\":" << board_wall << ",\"board_cpu_s\":" << board_cpu
         << ",\"sender_clue_wall_s\":" << send_wall << ",\"sender_clue_cpu_s\":" << send_cpu
         << ",\"clue_wire_bytes\":" << clue_bytes.size() << ",\"clue_file_bytes\":" << clue_file
         << ",\"maxrss_kb\":" << usage_now().maxrss_kb << "}" << endl;
    return 0;
}

int detect(const string &dir, const string &digest_out) {
    // One-time setup: the detector stores the receiver's evaluation and detection keys.
    Timer t_setup;
    SEALContext context = make_context();
    ddctx::set(context);
    RelinKeys relin = load_key<RelinKeys>(context, dir + "/relin_keys.bin");
    GaloisKeys gal = load_key<GaloisKeys>(context, dir + "/galois_keys.bin");
    const auto relin_full = relin.save_size(compr_mode_type::none);
    const auto gal_full = gal.save_size(compr_mode_type::none);
    ddctx::set_eval_keys(std::move(relin), std::move(gal));
    vector<Ciphertext> pk_detect = DeserializePublicKeyDetect(read_file(dir + "/pk_detect.bin"));
    const double setup_wall = t_setup.wall(), setup_cpu = t_setup.cpu();
    const long rss_after_setup = usage_now().maxrss_kb;

    // One poll: everything gen_encrypted_digest() does, including the switching-key
    // precomputation it repeats on every call and reading the clues from disk.
    Timer t_poll;
    Ciphertext digest = gen_encrypted_digest(pk_detect);
    const double poll_wall = t_poll.wall(), poll_cpu = t_poll.cpu();

    const string digest_bytes = SerializeDigest(digest);
    write_file(digest_out, digest_bytes);

    cout << fixed << setprecision(6) << "RESULT {\"tool\":\"omr\",\"phase\":\"detect\",\"n\":"
         << ddctx::num_transactions << ",\"setup_wall_s\":" << setup_wall << ",\"setup_cpu_s\":" << setup_cpu
         << ",\"wall_s\":" << poll_wall << ",\"cpu_s\":" << poll_cpu
         << ",\"maxrss_kb\":" << usage_now().maxrss_kb << ",\"maxrss_after_setup_kb\":" << rss_after_setup
         << ",\"digest_bytes\":" << digest_bytes.size() << ",\"relin_keys_expanded_bytes\":" << relin_full
         << ",\"galois_keys_expanded_bytes\":" << gal_full << "}" << endl;
    return 0;
}

int decode(const string &dir, const string &digest_path) {
    // One-time receiver state: the BFV context and the secret key.
    Timer t_setup;
    ddctx::set(make_context());
    SecretKey sk_decode = DeserializeSecretKeyDecode(read_file(dir + "/sk_decode.bin"));
    const double setup_wall = t_setup.wall(), setup_cpu = t_setup.cpu();

    const string digest_bytes = read_file(digest_path);

    // Per poll: parse the digest, decrypt it and recover the absolute indices.
    Timer t_poll;
    Ciphertext digest = DeserializeDigest(digest_bytes);
    vector<uint64_t> values = decode_digest(digest, sk_decode);
    vector<uint64_t> indices = digest_to_indices(values);
    const double poll_wall = t_poll.wall(), poll_cpu = t_poll.cpu();

    cout << fixed << setprecision(6) << "RESULT {\"tool\":\"omr\",\"phase\":\"decode\""
         << ",\"setup_wall_s\":" << setup_wall << ",\"setup_cpu_s\":" << setup_cpu
         << ",\"wall_s\":" << poll_wall << ",\"cpu_s\":" << poll_cpu
         << ",\"maxrss_kb\":" << usage_now().maxrss_kb << ",\"digest_bytes\":" << digest_bytes.size()
         << ",\"slots\":" << values.size() << ",\"matches\":[" << join(indices) << "]}" << endl;
    return 0;
}

// Board side (not a role cost): writes all N stored clues, in the prototype's clue wire format
// (SerializeClue), into one file. That file is what a receiver downloads for a local scan.
int export_board(int n, const string &out) {
    if (n != ddctx::num_transactions)
        throw runtime_error("this binary was built for N = " + to_string(ddctx::num_transactions) +
                            ", not " + to_string(n));
    auto params = srPKEParam();
    Timer t;
    ofstream f(out, ios::binary | ios::trunc);
    if (!f)
        throw runtime_error("cannot open " + out + " for writing");
    size_t total = 0, per_clue = 0;
    vector<srPKECiphertext> batch;
    const int chunk = 32768;
    for (int start = 0; start < n; start += chunk) {
        loadClues_dos(batch, start, min(n, start + chunk), params);
        for (const auto &c : batch) {
            const string w = SerializeClue(c);
            if (per_clue == 0)
                per_clue = w.size();
            else if (w.size() != per_clue)
                throw runtime_error("clues have different serialized sizes");
            f.write(w.data(), static_cast<streamsize>(w.size()));
            total += w.size();
        }
        batch.clear();
    }
    f.close();
    if (f.fail())
        throw runtime_error("write to " + out + " failed");
    cout << fixed << setprecision(6) << "RESULT {\"tool\":\"omr\",\"phase\":\"board_export\",\"n\":" << n
         << ",\"wall_s\":" << t.wall() << ",\"board_bytes\":" << total << ",\"clue_wire_bytes\":" << per_clue
         << "}" << endl;
    return 0;
}

// Receiver (experiment 2): downloads every clue and tests each one locally with its srPKE key.
int local_scan(const string &dir, const string &board_path, int threads) {
    auto params = srPKEParam();

    Timer t_setup;
    srPKEsk sk = deserialize_srpke_sk(read_file(dir + "/sk_clue.bin"), params.q);
    vector<vector<uint64_t>> s(params.ell, vector<uint64_t>(params.n1));
    for (int l = 0; l < params.ell; l++)
        for (int i = 0; i < params.n1; i++)
            s[l][i] = sk[l][i].ConvertToInt();
    const double setup_wall = t_setup.wall(), setup_cpu = t_setup.cpu();

    // One buffer of exactly the file size, so peak RSS is the downloaded board plus the key.
    Timer t_load;
    string board;
    {
        ifstream f(board_path, ios::binary | ios::ate);
        if (!f)
            throw runtime_error("cannot open " + board_path);
        board.resize(static_cast<size_t>(f.tellg()));
        f.seekg(0);
        f.read(&board[0], static_cast<streamsize>(board.size()));
        if (!f)
            throw runtime_error("short read from " + board_path);
    }
    const double load_wall = t_load.wall();
    const size_t per = size_t(4 + 8 * params.n1) + size_t(4 + 8 * params.ell);  // SerializeClue length
    if (board.size() % per != 0)
        throw runtime_error("board is not a whole number of clues");
    const size_t n = board.size() / per;

    // Per poll: parse each downloaded clue and test it.
    Timer t_scan;
    threads = max(1, threads);
    vector<vector<uint64_t>> found(threads);
    auto work = [&](int t) {
        const size_t lo = n * size_t(t) / size_t(threads), hi = n * size_t(t + 1) / size_t(threads);
        const string_view all(board);
        for (size_t k = lo; k < hi; k++) {
            const srPKECiphertext ct = DeserializeClue(all.substr(k * per, per), params.q);
            if (clue_is_pertinent(ct, s, params))
                found[t].push_back(k);
        }
    };
    if (threads == 1) {
        work(0);
    } else {
        vector<thread> pool;
        for (int t = 0; t < threads; t++)
            pool.emplace_back(work, t);
        for (auto &th : pool)
            th.join();
    }
    vector<uint64_t> matches;
    for (auto &v : found)
        matches.insert(matches.end(), v.begin(), v.end());
    sort(matches.begin(), matches.end());
    const double scan_wall = t_scan.wall(), scan_cpu = t_scan.cpu();

    cout << fixed << setprecision(6) << "RESULT {\"tool\":\"omr\",\"phase\":\"receiver_local_scan\",\"n\":" << n
         << ",\"threads\":" << threads << ",\"setup_wall_s\":" << setup_wall << ",\"setup_cpu_s\":" << setup_cpu
         << ",\"load_s\":" << load_wall << ",\"wall_s\":" << scan_wall << ",\"cpu_s\":" << scan_cpu
         << ",\"us_per_clue_cpu\":" << scan_cpu / double(n) * 1e6 << ",\"maxrss_kb\":" << usage_now().maxrss_kb
         << ",\"download_bytes\":" << board.size() << ",\"clue_wire_bytes\":" << per
         << ",\"matches\":[" << join(matches) << "]}" << endl;
    return 0;
}

}  // namespace bench

int main(int argc, char **argv) {
    try {
        const vector<string> a(argv + 1, argv + argc);
        if (a.size() == 2 && a[0] == "receiver-keygen")
            return bench::receiver_keygen(a[1]);
        if (a.size() == 4 && a[0] == "build-board")
            return bench::build_board(stoi(a[1]), stoi(a[2]), a[3]);
        if (a.size() == 3 && a[0] == "detect")
            return bench::detect(a[1], a[2]);
        if (a.size() == 3 && a[0] == "decode")
            return bench::decode(a[1], a[2]);
        if (a.size() == 3 && a[0] == "export-board")
            return bench::export_board(stoi(a[1]), a[2]);
        if ((a.size() == 3 || a.size() == 4) && a[0] == "local-scan")
            return bench::local_scan(a[1], a[2], a.size() == 4 ? stoi(a[3]) : 1);
        cerr << "usage: omr_bench receiver-keygen KEYDIR | build-board N INDEX PK_CLUE | "
                "detect KEYDIR DIGEST_OUT | decode KEYDIR DIGEST | export-board N OUT | "
                "local-scan KEYDIR BOARD [THREADS]" << endl;
        return 2;
    } catch (const exception &e) {
        cerr << "ERR: " << e.what() << endl;
        return 1;
    }
}
