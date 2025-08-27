// seufinder.cpp  (C++17)
// 宇宙線SEU観測用: 決定論パターンを書いて静置→周回走査→二重確認→CSV記録
// 注意: 大量のRAMを掴むので物理メモリの余裕を十分に確保してください。

#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
  #define NOMINMAX
  #include <windows.h>
#else
  #include <sys/mman.h>
  #include <unistd.h>
#endif

#if defined(__x86_64__) || defined(_M_X64)
  #include <immintrin.h>
  static inline void clflush64(const void* p){ _mm_clflush(p); }
#else
  static inline void clflush64(const void*){}
#endif

using u64 = uint64_t;

struct Config {
  size_t gib = 8;          // 確保サイズ [GiB]
  int interval_sec = 60;   // 走査間隔 [sec]
  int threads = 2;
  int verify_reads = 2;    // 再読回数（>=1）
  bool use_clflush = false;
  std::string out_csv = "seufinder.csv";
};

static inline std::string now_iso8601(){
  using namespace std::chrono;
  auto t = system_clock::now();
  std::time_t tt = system_clock::to_time_t(t);
  auto tm = *std::gmtime(&tt);
  auto us = duration_cast<microseconds>(t.time_since_epoch()).count() % 1000000;
  std::ostringstream os;
  os << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S") << "." << std::setw(6) << std::setfill('0') << us << "Z";
  return os.str();
}

// アドレスindex→決定論64bitパターン（軽量LCG）
static inline u64 pattern_from_index(u64 idx){
  u64 x = idx + 0x9E3779B97F4A7C15ull; // golden ratio offset
  x ^= x >> 33; x *= 0xff51afd7ed558ccdULL;
  x ^= x >> 33; x *= 0xc4ceb9fe1a85ec53ULL;
  x ^= x >> 33;
  // さらにビットに偏りを与えないため、AAA.../555...混合
  return x ^ 0xAAAAAAAAAAAAAAAAull ^ (x<<1);
}

struct Region {
  volatile u64* base = nullptr;
  size_t words = 0;
};

#ifdef _WIN32
bool lock_pages(void* p, size_t bytes){
  return VirtualLock(p, bytes) != 0;
}
void* alloc_pages(size_t bytes){
  void* p = VirtualAlloc(nullptr, bytes, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
  return p;
}
void free_pages(void* p){
  VirtualFree(p, 0, MEM_RELEASE);
}
#else
bool lock_pages(void* p, size_t bytes){
  return mlock(p, bytes) == 0;
}
void* alloc_pages(size_t bytes){
  void* p = nullptr;
  // ページ整列
  if(posix_memalign(&p, sysconf(_SC_PAGESIZE), bytes)!=0) return nullptr;
  return p;
}
void free_pages(void* p){
  free(p);
}
#endif

struct Stat {
  std::atomic<uint64_t> scanned{0};   // 読み取り総ワード
  std::atomic<uint64_t> detected{0};  // 反転確定件数
} gstat;

std::mutex g_log_mtx;

void scan_worker(const Region reg, int verify_reads, bool use_clflush, std::ofstream& csv, int tid){
  // 各スレッドで領域を分担
  const u64* const base_ro = reinterpret_cast<const u64*>(reg.base);
  volatile u64* const base_rw = reg.base;

  auto log_event = [&](u64 idx, u64 expect, u64 got, int repro_count){
    std::lock_guard<std::mutex> lk(g_log_mtx);
    csv << now_iso8601() << ","
        << tid << ","
        << idx << ","
        << std::hex << expect << ","
        << got << ","
        << (expect ^ got) << std::dec << ","
        << repro_count << "\n";
    csv.flush();
  };

  for(size_t i=0;i<reg.words;i++){
    u64 idx = i;
    u64 exp = pattern_from_index(idx);
    // 1st read
    if(use_clflush) clflush64((const void*)&base_ro[i]);
    u64 v1 = base_ro[i];

    if(v1 != exp){
      // 再現確認
      int ok=0;
      u64 vlast = v1;
      for(int r=1;r<verify_reads;r++){
        if(use_clflush) clflush64((const void*)&base_ro[i]);
        std::this_thread::sleep_for(std::chrono::microseconds(50));
        u64 vr = base_ro[i];
        vlast = vr;
        if(vr != exp) ok++;
      }
      if(ok == verify_reads-1){
        gstat.detected++;
        log_event(idx, exp, vlast, verify_reads);
        // 修復
        base_rw[i] = exp;
      }
    }
    gstat.scanned++;
  }
}

int main(int argc, char** argv){
  Config cfg;
  for(int i=1;i<argc;i++){
    std::string a = argv[i];
    if(a=="-m" && i+1<argc){ cfg.gib = std::stoull(argv[++i]); }
    else if(a=="-i" && i+1<argc){ cfg.interval_sec = std::stoi(argv[++i]); }
    else if(a=="-t" && i+1<argc){ cfg.threads = std::stoi(argv[++i]); }
    else if(a=="--verify" && i+1<argc){ cfg.verify_reads = std::stoi(argv[++i]); }
    else if(a=="--clflush"){ cfg.use_clflush = true; }
    else if(a=="-o" && i+1<argc){ cfg.out_csv = argv[++i]; }
    else {
      std::cerr << "Usage: " << argv[0] << " -m <GiB> -i <sec> -t <threads> --verify <N> [--clflush] -o <csv>\n";
      return 1;
    }
  }

  const size_t bytes = cfg.gib * (size_t(1) << 30);
  std::cerr << "[INFO] Allocating " << cfg.gib << " GiB ...\n";

  void* mem = alloc_pages(bytes);
  if(!mem){
    std::cerr << "[ERR] allocation failed\n"; return 2;
  }
  if(!lock_pages(mem, bytes)){
    std::cerr << "[WARN] page lock failed; continuing without mlock/VirtualLock\n";
  }

  Region region;
  region.base = reinterpret_cast<volatile u64*>(mem);
  region.words = bytes / sizeof(u64);

  // 初期化（決定論パターン書き込み）
  std::cerr << "[INFO] Initializing pattern...\n";
  #pragma omp parallel for
  for(long long i=0;i<(long long)region.words;i++){
    region.base[i] = pattern_from_index((u64)i);
  }

  std::ofstream csv(cfg.out_csv, std::ios::out);
  csv << "timestamp_utc,thread,index,expected_hex,observed_hex,xor_hex,repro_reads\n";
  csv.flush();

  std::cerr << "[INFO] Start monitoring: interval="<<cfg.interval_sec<<"s threads="<<cfg.threads
            << " verify="<<cfg.verify_reads<<" clflush="<<(cfg.use_clflush?"on":"off")<<"\n";

  // スレッドごとに領域分割
  auto run_scan_once = [&](){
    std::vector<std::thread> th;
    size_t chunk = region.words / cfg.threads;
    for(int t=0;t<cfg.threads;t++){
      size_t begin = t * chunk;
      size_t end   = (t==cfg.threads-1) ? region.words : begin + chunk;
      Region sub{ region.base + begin, end - begin };
      th.emplace_back([&, sub, t](){
        // スレッド専用ファイル共有
        scan_worker(sub, cfg.verify_reads, cfg.use_clflush, csv, t);
      });
    }
    for(auto& x: th) x.join();
  };

  // 周期走査ループ
  while(true){
    auto t0 = std::chrono::steady_clock::now();
    run_scan_once();
    auto t1 = std::chrono::steady_clock::now();
    auto spent = std::chrono::duration_cast<std::chrono::seconds>(t1 - t0).count();
    if(spent < cfg.interval_sec){
      std::this_thread::sleep_for(std::chrono::seconds(cfg.interval_sec - spent));
    }
    std::cerr << "[STAT] scanned="<< gstat.scanned.load() << " words, detected="<< gstat.detected.load() << "\n";
  }

  // 到達しない
  free_pages(mem);
  return 0;
}
