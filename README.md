# seu-checker

SEU (Single Event Upset) の検出・実験用 C++プログラムです。

## 使い方

1. コンパイル

```sh
g++ -std=c++17 seufinder.cpp -o seufinder
```

2. 実行

```sh
./seufinder
```

## ファイル構成

- `seufinder.cpp`: メインの C++ソースコード
- `spec.md`: 仕様や実験内容の説明

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
