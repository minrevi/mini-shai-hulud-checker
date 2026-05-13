# mini-shai-hulud-checker

Mini Shai-Hulud / Shai-Hulud-like supply-chain compromise の既知ローカル IoC を確認するための、読み取り専用ローカルスキャナーです。

このリポジトリは、macOS / Linux の開発者端末上で、既知の不審プロセス、永続化設定、依存ファイル、AI/エディタ設定、シェル履歴のヒントを確認することを目的としています。

## 重要な注意

- このスクリプトは読み取り専用です。
- ファイル削除、プロセス停止、トークン失効、パッケージインストール、設定変更は行いません。
- `GREEN` は「既知のローカル IoC が見つからなかった」という意味であり、認証情報の漏えいがなかったことの証明ではありません。
- `YELLOW` は感染確定ではありません。正当なパッケージや設定でも検出される可能性があります。
- `RED` が出た場合は、同じ端末上でトークン失効や証跡削除を行わず、証拠保全とセキュリティ担当への連絡を優先してください。

## 使い方

実行権限を付けます。

```bash
chmod +x ./mini-shai-hulud-scan.sh
```

カレントディレクトリと、よくある開発ディレクトリをスキャンします。

```bash
./mini-shai-hulud-scan.sh
```

対象ディレクトリを明示してスキャンします。

```bash
./mini-shai-hulud-scan.sh ~/dev ~/work ~/workspace ~/ghq
```

結果は日本語で標準出力に表示され、同時に以下の形式でログ保存されます。

```text
mini-shai-hulud-scan-<host>-<yyyymmdd-HHMMSS>.log
```

## 検出対象

主に以下を確認します。

- 既知の不審プロセスやコマンドライン
- macOS LaunchAgent / Linux systemd user service / autostart の既知永続化パス
- `router_init.js`、`tanstack_runner.js`、`bun_environment.js`、`setup_bun.js` などの不審ファイル名
- 既知の exfil domain、キャンペーン文字列、悪性依存パターン
- 影響報告がある、またはレビューが必要なパッケージ scope / package name
- Claude Code、VS Code、Cursor、Windsurf、MCP、GitHub Actions などの実行可能 hook / task / command パターン
- 依存インストール・更新コマンドのシェル履歴ヒント
- `safe-chain` の導入状況

## 終了コード

- `0`: `GREEN`。既知の危険な痕跡は見つかりませんでした。
- `1`: `RED`。既知の感染インジケータが見つかりました。
- `2`: `YELLOW`。確認が必要な項目が見つかりました。感染確定ではありません。

## 結果別の対応

### GREEN

既知の危険な痕跡は見つかっていません。この結果とレポート保存先を担当者へ報告してください。

ただし、`GREEN` は認証情報（ログイン情報やトークン等）が盗まれていないことの証明ではありません。このスキャンでは、2026-04-29 以降に依存関係の install/update があったか、またはこの端末が GitHub / npm / cloud などの重要な権限を持っているかは確定できません。該当する可能性がある場合は、担当者が別途確認してください。

### YELLOW

感染確定ではありません。この結果とレポート保存先を担当者へ報告してください。自分でファイル削除や設定変更をせず、担当者の確認を待ってください。

特に `.github/workflows/*.yml` やエディタ設定は、通常の開発用自動処理でも検出されます。この種類の検出はファイルごとではなく、1つのブロックに集約して表示されます。表示された設定が業務上正しいものかは、このスキャンだけでは確定できません。

必要に応じて、クリーンな環境や CI 上で再現確認します。

### RED

既知の感染インジケータが見つかっています。

推奨対応:

1. 端末をネットワークから切断する。
2. 同じ端末から GitHub / npm / cloud トークンを失効しない。
3. 不審ファイルを削除する前に証拠を保全する。
4. 出力ログと不審ファイルを保存する。
5. セキュリティ / IT 担当へ連絡する。
6. 永続化の把握後、別の信頼できる端末から認証情報をローテーションする。

## 開発者向けチェック

構文チェック:

```bash
bash -n ./mini-shai-hulud-scan.sh
```

空ディレクトリに対するスモークテスト:

```bash
tmpdir="$(mktemp -d)"
./mini-shai-hulud-scan.sh "$tmpdir"
status=$?
rm -rf "$tmpdir"
exit "$status"
```

## 制限

- ローカルファイルとローカル設定の既知 IoC 確認に限定しています。
- GitHub audit log、npm publish history、CI log、cloud audit log は確認しません。
- Shell history の時刻は環境によって信頼できない場合があります。
- 検出パターンは既知情報ベースです。未知の変種や痕跡削除済みの侵害は検出できない可能性があります。

## ライセンス

MIT License
