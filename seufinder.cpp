// seufinder.cpp  (C++17)
// 宇宙線起因DRAMビット反転“観測”用：決定論パターンを書いて静置→周回走査→再現確認→CSV記録
// さらに各スキャン時にASCIIグリッド(0-9)で可視化ログを追記
// 注意: 大量のRAMを掴むので空き物理メモリに余裕を確保してください。

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
#include <csignal>

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
  size_t gib = 1;            // 確保サイズ [GiB]
  int interval_sec = 900;    // 走査間隔 [sec] (既定15分)
  int threads = 1;
  int verify_reads = 2;      // 再読回数（>=1）
  bool use_clflush = false;  // キャッシュフラッシュ
  std::string out_csv = "seufinder.csv";
  long iterations = -1;      // -1:無限 / >=1:回数指定
  bool lock_pages = false;   // mlock/VirtualLock
};

struct VizCfg {
  std::string map_path = ""; // 空なら可視化なし
  int cols = 20;
  int rows = 12;
  bool clamp_0_9 = true;     // 0-9 に丸める（10以上は9）
};

static std::atomic<bool> g_stop{false};

static inline std::string now_iso8601_utc(){
  using namespace std::chrono;
  auto tp = system_clock::now();
  std::time_t tt = system_clock::to_time_t(tp);
  auto tm = *std::gmtime(&tt);
  auto us = duration_cast<microseconds>(tp.time_since_epoch()).count() % 1000000;
  std::ostringstream os;
  os << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S") << "." << std::setw(6) << std::setfill('0') << us << "Z";
  return os.str();
}

// アドレス(ワード)index→決定論64bitパターン（軽量ハッシュ）
static inline u64 pattern_from_index(u64 idx){
  u64 x = idx + 0x9E3779B97F4A7C15ull; // golden ratio offset
  x ^= x >> 33; x *= 0xff51afd7ed558ccdULL;
  x ^= x >> 33; x *= 0xc4ceb9fe1a85ec53ULL;
  x ^= x >> 33;
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

static void on_signal(int){
  g_stop.store(true);
}

static void sleep_until_or_stop(std::chrono::steady_clock::time_point tp){
  while(!g_stop.load()){
    auto now = std::chrono::steady_clock::now();
    if(now >= tp) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
}

int main(int argc, char** argv){
  // --------------- 引数処理 ---------------
  Config cfg;
  VizCfg viz;
  for(int i=1;i<argc;i++){
    std::string a = argv[i];
    if(a=="-m" && i+1<argc){ cfg.gib = std::stoull(argv[++i]); }
    else if(a=="-i" && i+1<argc){ cfg.interval_sec = std::stoi(argv[++i]); }
    else if(a=="-t" && i+1<argc){ cfg.threads = std::stoi(argv[++i]); }
    else if(a=="--verify" && i+1<argc){ cfg.verify_reads = std::stoi(argv[++i]); }
    else if(a=="--clflush"){ cfg.use_clflush = true; }
    else if(a=="-o" && i+1<argc){ cfg.out_csv = argv[++i]; }
    else if(a=="--iterations" && i+1<argc){ cfg.iterations = std::stol(argv[++i]); }
    else if(a=="--mlock"){ cfg.lock_pages = true; }
    else if(a=="--viz-map" && i+1<argc){ viz.map_path = argv[++i]; }
    else if(a=="--viz-cols" && i+1<argc){ viz.cols = std::stoi(argv[++i]); }
    else if(a=="--viz-rows" && i+1<argc){ viz.rows = std::stoi(argv[++i]); }
    else if(a=="--viz-unclamped"){ viz.clamp_0_9 = false; }
    else if(a=="-h" || a=="--help"){
      std::cout <<
"seufinder - DRAM bit-flip monitor (C++17)\n"
"Usage: seufinder [options]\n"
"  -m <GiB>           Memory to occupy (default 1)\n"
"  -i <sec>           Scan interval seconds (default 900=15min)\n"
"  -t <threads>       Reader threads (default 1)\n"
"  --verify <N>       Re-read count per mismatch (default 2)\n"
"  --clflush          Use CLFLUSH before reads (x86_64 only)\n"
"  -o <csv>           CSV output path (default seufinder.csv)\n"
"  --iterations <K>   Run exactly K scans (default -1 infinite)\n"
"  --mlock            Try to mlock/VirtualLock pages\n"
"  --viz-map <path>   Append ASCII grid to this file each scan\n"
"  --viz-cols <n>     Grid columns (default 20)\n"
"  --viz-rows <n>     Grid rows (default 12)\n"
"  --viz-unclamped    Do not clamp counts to 0-9 (>=10 shown as A..Z)\n"
"  -h, --help         Show this help\n";
      return 0;
    }
  }

  // --------------- 初期セットアップ ---------------
  std::signal(SIGINT,  on_signal);
  std::signal(SIGTERM, on_signal);

  const size_t bytes = cfg.gib * (size_t(1) << 30);
  std::cerr << "[INFO] Allocating " << cfg.gib << " GiB (" << bytes << " bytes)...\n";
  void* mem = alloc_pages(bytes);
  if(!mem){
    std::cerr << "[ERR] allocation failed\n"; return 2;
  }
  if(cfg.lock_pages){
    if(lock_pages(mem, bytes)){
      std::cerr << "[INFO] pages locked\n";
    }else{
      std::cerr << "[WARN] page lock failed; continuing\n";
    }
  }

  Region region;
  region.base = reinterpret_cast<volatile u64*>(mem);
  region.words = bytes / sizeof(u64);

  std::cerr << "[INFO] Initializing pattern...\n";
  // シングルスレッドで十分速いが、長い場合は簡易並列
  auto init_worker = [&](size_t beg, size_t end){
    volatile u64* base = region.base;
    for(size_t i=beg;i<end;i++){
      base[i] = pattern_from_index((u64)i);
    }
  };
  {
    int init_threads = std::min(cfg.threads, std::max(1, cfg.threads));
    std::vector<std::thread> th;
    size_t chunk = region.words / init_threads;
    for(int t=0;t<init_threads;t++){
      size_t beg = t * chunk;
      size_t end = (t==init_threads-1) ? region.words : beg + chunk;
      th.emplace_back(init_worker, beg, end);
    }
    for(auto& x: th) x.join();
  }

  // CSVヘッダ
  std::ofstream csv(cfg.out_csv, std::ios::out | std::ios::app);
  if(!csv){
    std::cerr << "[ERR] cannot open csv: " << cfg.out_csv << "\n"; return 3;
  }
  // 既存ファイルにヘッダがない場合だけ付けたいが、簡便のため毎回はり直してもExcel等では問題ない
  csv << "timestamp_utc,thread,index,expected_hex,observed_hex,xor_hex,repro_reads\n";
  csv.flush();

  auto viz_write_frame = [&](const std::vector<uint32_t>& bins){
    if(viz.map_path.empty()) return;
    std::ofstream vf(viz.map_path, std::ios::app);
    if(!vf) return;
    vf << now_iso8601_utc() << "\n";
    auto encode = [&](uint32_t c)->char{
      if(viz.clamp_0_9){
        if(c==0) return '#';
        if(c>=9) return '9';
        return char('0'+c);
      }else{
        if(c==0) return '#';
        if(c<=9) return char('0'+c);
        if(c<=35) return char('A'+(c-10)); // 10..35 -> A..Z
        return '*'; // 36以上は*
      }
    };
    for(int r=0;r<viz.rows;r++){
      for(int c=0;c<viz.cols;c++){
        vf << encode(bins[(size_t)r*viz.cols + c]);
      }
      vf << "\n";
    }
    vf << "\n";
    vf.flush();
  };

  std::cerr << "[INFO] Start monitoring: interval="<<cfg.interval_sec<<"s threads="<<cfg.threads
            << " verify="<<cfg.verify_reads<<" clflush="<<(cfg.use_clflush?"on":"off")
            << " viz="<<(viz.map_path.empty()?"off":"on")<<"\n";

  auto scan_once = [&](uint64_t iter){
    // 可視化ビン
    size_t cells = (size_t)std::max(1, viz.cols * viz.rows);
    const size_t words_per_cell = std::max<size_t>(1, region.words / cells);

    // スレッドごとのローカルbinsを最後にリダクション（mutex不要）
    std::vector<std::vector<uint32_t>> local_bins(cfg.threads, std::vector<uint32_t>(cells, 0));

    std::mutex log_mtx; // CSVへの同時出力を保護
    auto log_event = [&](int tid, u64 idx, u64 exp, u64 got, int repro){
      std::lock_guard<std::mutex> lk(log_mtx);
      csv << now_iso8601_utc() << ","
          << tid << ","
          << idx << ","
          << std::hex << exp << ","
          << got << ","
          << (exp ^ got) << std::dec << ","
          << repro << "\n";
    };

    std::vector<std::thread> th;
    size_t chunk = region.words / cfg.threads;

    for(int t=0;t<cfg.threads;t++){
      size_t begin = t * chunk;
      size_t end   = (t==cfg.threads-1) ? region.words : begin + chunk;

      th.emplace_back([&, t, begin, end](){
  const volatile u64* base_ro = reinterpret_cast<const volatile u64*>(region.base);
        volatile u64* base_rw = region.base;
        auto& bins = local_bins[t];

        for(size_t i=begin;i<end;i++){
          if(g_stop.load()) return;
          u64 exp = pattern_from_index((u64)i);
          if(cfg.use_clflush) clflush64((const void*)&base_ro[i]);
          u64 v1 = base_ro[i];

          if(v1 != exp){
            int ok=0; u64 vlast=v1;
            for(int r=1;r<cfg.verify_reads;r++){
              if(cfg.use_clflush) clflush64((const void*)&base_ro[i]);
              std::this_thread::sleep_for(std::chrono::microseconds(50));
              u64 vr = base_ro[i]; vlast=vr;
              if(vr != exp) ok++;
            }
            if(ok == cfg.verify_reads-1){
              gstat.detected++;
              log_event(t, (u64)i, exp, vlast, cfg.verify_reads);
              // 修復
              base_rw[i] = exp;

              if(!viz.map_path.empty()){
                size_t bin = std::min(cells-1, (i / words_per_cell));
                if(viz.clamp_0_9){
                  if(bins[bin] < 9) bins[bin] += 1; // 0-9に丸め
                }else{
                  bins[bin] += 1;
                }
              }
            }
          }
          gstat.scanned++;
        }
      });
    }
    for(auto& x: th) x.join();

    // ローカル→グローバル結合
    if(!viz.map_path.empty()){
      std::vector<uint32_t> final_bins(cells, 0);
      for(int t=0;t<cfg.threads;t++){
        for(size_t k=0;k<cells;k++){
          if(viz.clamp_0_9){
            // 0-9で足し合わせ時も飽和
            uint32_t sum = final_bins[k] + local_bins[t][k];
            final_bins[k] = (sum > 9) ? 9 : sum;
          }else{
            final_bins[k] += local_bins[t][k];
          }
        }
      }
      viz_write_frame(final_bins);
    }
    csv.flush();
  };

  // --------------- 周期走査ループ ---------------
  uint64_t iter = 0;
  while(!g_stop.load()){
    auto t0 = std::chrono::steady_clock::now();
    scan_once(iter);
    iter++;

    std::cerr << "[STAT] iter="<<iter<<" scanned="<< gstat.scanned.load()
              << " words, detected="<< gstat.detected.load() << "\n";

    if(cfg.iterations > 0 && (long)iter >= cfg.iterations) break;

    auto next_tp = t0 + std::chrono::seconds(cfg.interval_sec);
    sleep_until_or_stop(next_tp);
  }

  free_pages(mem);
  std::cerr << "[INFO] bye\n";
  return 0;
}
