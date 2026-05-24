package main

import (
	"reflect"
	"testing"
)

// TestDispatchRules 覆盖需求 §5 的所有派发规则边界情况：
//   1. 无参数 → 前台模式；
//   2. 第一个参数以 '-' 开头 → 前台模式，args 保持原样；
//   3. 已知子命令 → 进入分支；
//   4. 未知子命令 → name="?"。
func TestDispatchRules(t *testing.T) {
	tests := []struct {
		name     string
		argv     []string
		wantName string
		wantArgs []string
	}{
		{
			name:     "无参数走前台",
			argv:     []string{"sip-ban"},
			wantName: "",
			wantArgs: nil,
		},
		{
			name:     "短横线参数走前台兼容旧 CLI",
			argv:     []string{"sip-ban", "-i", "eth0"},
			wantName: "",
			wantArgs: []string{"-i", "eth0"},
		},
		{
			name:     "长横线也算前台（与 -i 同档）",
			argv:     []string{"sip-ban", "--help"},
			wantName: "",
			wantArgs: []string{"--help"},
		},
		{
			name:     "start 子命令带 -d",
			argv:     []string{"sip-ban", "start", "-d", "-i", "eth0"},
			wantName: "start",
			wantArgs: []string{"-d", "-i", "eth0"},
		},
		{
			name:     "status 子命令",
			argv:     []string{"sip-ban", "status"},
			wantName: "status",
			wantArgs: []string{},
		},
		{
			name:     "stop 子命令带自定义 pid",
			argv:     []string{"sip-ban", "stop", "-pid", "/tmp/x.pid"},
			wantName: "stop",
			wantArgs: []string{"-pid", "/tmp/x.pid"},
		},
		{
			name:     "restart 子命令",
			argv:     []string{"sip-ban", "restart"},
			wantName: "restart",
			wantArgs: []string{},
		},
		{
			name:     "未知子命令",
			argv:     []string{"sip-ban", "frobnicate"},
			wantName: "?",
			wantArgs: []string{"frobnicate"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dispatch(tt.argv)
			if got.name != tt.wantName {
				t.Errorf("name = %q, want %q", got.name, tt.wantName)
			}
			if !reflect.DeepEqual(got.args, tt.wantArgs) && !(len(got.args) == 0 && len(tt.wantArgs) == 0) {
				t.Errorf("args = %v, want %v", got.args, tt.wantArgs)
			}
		})
	}
}

// TestStripFlag 验证 stripFlag 能从参数列表里干净移除指定 flag。
func TestStripFlag(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		flag string
		want []string
	}{
		{"移除 -d", []string{"-d", "-i", "eth0"}, "-d", []string{"-i", "eth0"}},
		{"无 -d 不变", []string{"-i", "eth0"}, "-d", []string{"-i", "eth0"}},
		{"多个 -d 全部移除", []string{"-d", "-i", "eth0", "-d"}, "-d", []string{"-i", "eth0"}},
		{"空参数列表", []string{}, "-d", []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripFlag(tt.in, tt.flag)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
