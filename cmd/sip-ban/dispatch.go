// Package main 的子命令分发逻辑。
//
// 派发规则（需求 §5，必须严格按以下顺序判断）：
//  1. len(os.Args) == 1                            → 走旧的前台模式（无参数兼容）。
//  2. os.Args[1] 以 '-' 开头                       → 视作旧 CLI 参数，走前台模式。
//  3. os.Args[1] 是已知子命令（start/status/stop/restart）→ 进入子命令分支。
//  4. 其他情况                                     → 打印 usage 并退出码 1。
//
// 这样旧用户的 `sudo ./sip-ban -i eth0` 完全不变；新用户用 `sip-ban start [-d]`。
package main

import (
	"fmt"
	"io"
	"os"
)

// command 表示分发结果。
//   - name == ""：前台模式（兼容旧 CLI）。
//   - name == "start" / "status" / "stop" / "restart"：进入对应子命令。
//   - args：去掉子命令后的剩余参数列表。
type command struct {
	name string
	args []string
}

// knownSubcommands 是所有 daemon 子命令的白名单。
var knownSubcommands = map[string]struct{}{
	"start":   {},
	"status":  {},
	"stop":    {},
	"restart": {},
}

// dispatch 把 os.Args 切片映射到 command。
//
// 规则严格按 §5：
//   - 输入 ["sip-ban"]：返回前台模式；
//   - 输入 ["sip-ban", "-i", "eth0", ...]：返回前台模式，args = ["-i", "eth0", ...]；
//   - 输入 ["sip-ban", "start", ...]：返回 start 子命令；
//   - 输入 ["sip-ban", "unknown"]：返回 name="?" 以便上层打印 usage。
//
// 不变量：调用 dispatch 后，name == "?" 时 args 保留原始切片以便错误信息复用。
func dispatch(argv []string) command {
	if len(argv) <= 1 {
		return command{name: "", args: nil}
	}
	first := argv[1]
	if len(first) > 0 && first[0] == '-' {
		// 旧 CLI 风格，整条命令行透传给前台模式
		return command{name: "", args: argv[1:]}
	}
	if _, ok := knownSubcommands[first]; ok {
		return command{name: first, args: argv[2:]}
	}
	return command{name: "?", args: argv[1:]}
}

// usage 把使用说明写到 w。
func usage(w io.Writer) {
	fmt.Fprintln(w, `用法:
  sip-ban [子命令] [参数]

子命令:
  (无)              前台运行（兼容旧行为）
  start             启动；加 -d 进入后台
  status            查询运行状态
  stop              停止后台进程
  restart           等价于 stop && start -d

start 专属参数:
  -d                后台运行（仅 Linux）
  -pid <path>       PID 文件路径
  -log <path>       日志文件路径

start 同时支持所有现有捕获参数：-i / -p / -P / -rt / -rn / -it / -in / -ipdb

status / stop / restart 只接受 -pid <path>。`)
}

// printUsageAndExit 打印 usage 并以指定退出码退出。
// 抽出来主要是为了在 dispatch == "?" 与显式帮助两个分支共享。
func printUsageAndExit(code int) {
	usage(os.Stderr)
	os.Exit(code)
}
