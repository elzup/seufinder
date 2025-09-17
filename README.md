# SeuFinder

SEU (Single Event Upset) の検出・実験用 C++プログラムです。

## 使い方

1. C++ 版コンパイル

```sh
g++ -std=c++17 seufinder.cpp -o seufinder
```

2. 実行

```sh
./seufinder
```

![スクリーンショット](ss.png)

### Rust 版

1. ビルド

```sh
cargo build --release
```

2. 実行

```sh
./target/release/seufinder-rs
```

Rust 版も C++ 版と同じオプションをサポートしています。

## ファイル構成

- `seufinder.cpp`: メインの C++ソースコード
- `Cargo.toml`: Rust 版のビルド設定
- `src/main.rs`: Rust 版のエントリポイント
- `spec.md`: 仕様や実験内容の説明

## 主なオプション

- `-m <GiB>`: 占有メモリサイズ（GiB 単位、例: `-m 1`）
- `-i <sec>`: 走査間隔（秒、例: `-i 900`）
- `-t <num>`: スレッド数（例: `-t 1`）
- `--verify <num>`: 再読回数（例: `--verify 2`）
- `-o <file>`: 結果 CSV ファイル名（例: `-o seufinder.csv`）
- `--viz-map <file>`: 可視化ログ出力先（例: `--viz-map viz.txt`）
- `--viz-cols <num>`: 可視化グリッドの列数（例: `--viz-cols 20`）
- `--viz-rows <num>`: 可視化グリッドの行数（例: `--viz-rows 12`）
- `--clflush`: キャッシュフラッシュ有効化
- `--lock-pages`: メモリページロック

## 機能概要

- 決定論的パターンを書き込み、一定間隔で走査・再現確認
- DRAM ビット反転（SEU）を検出し CSV 記録
- ASCII グリッドによる可視化ログ出力
- 大量の物理メモリを使用するため、十分な空きメモリが必要

## ライセンス

MIT

```
# 1GiB占有 / 15分おき / 単スレッド / 再読2回 / CLFLUSHなし
./seufinder -m 1 -i 900 -t 1 --verify 2 \
  -o seufinder.csv --viz-map viz.txt --viz-cols 20 --viz-rows 12
```

```
g++ -std=c++17 seufinder.cpp -o seufinder
```
