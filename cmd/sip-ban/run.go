// Package main 的核心运行逻辑（与 main 函数分离便于复用）。
package main

import (
	"context"
	"fmt"

	"sip-ban/internal/analyzer"
	"sip-ban/internal/capture"
	"sip-ban/internal/config"
	"sip-ban/internal/firewall"
	"sip-ban/internal/geoip"
	"sip-ban/internal/sip"
)

// Run 启动完整的捕获 / 分析 / 封禁流程。
//
// 调用约定：
//   - ctx 被取消后，函数会等待所有 capture 协程退出再返回；
//   - 启动阶段的依赖初始化失败（firewall / geoip）只会打警告，
//     不会让程序直接挂掉；这与旧版前台行为保持一致；
//   - 仅当 capture.Manager.Start 列举网卡失败时才会返回错误。
func Run(ctx context.Context, cfg *config.Config) error {
	// 初始化防火墙管理器。失败仅警告——非 root 或缺 iptables 也允许跑日志。
	fw, err := firewall.New()
	if err != nil {
		fmt.Printf("警告: Iptables初始化失败: %s\n", err)
	}

	// 初始化 IP 地理位置检查器。同样只警告。
	geoChecker, err := geoip.New(cfg.IPDBPath)
	if err != nil {
		fmt.Printf("警告: IP数据库加载失败: %s\n", err)
	}

	// 基于 SIP 方法的封禁规则
	banRules := map[string]*analyzer.BanRule{
		sip.MethodInvite.String(): {
			FindTime: cfg.InviteFindTime,
			MaxRetry: cfg.InviteMaxRetry,
		},
		sip.MethodRegister.String(): {
			FindTime: cfg.RegisterFindTime,
			MaxRetry: cfg.RegisterMaxRetry,
		},
	}

	// 基于响应码的封禁规则：
	// 407 / 403 复用 INVITE 的窗口，401 复用 REGISTER 的窗口。
	banRuleCodes := map[int]*analyzer.BanRule{
		407: banRules[sip.MethodInvite.String()],
		403: banRules[sip.MethodInvite.String()],
		401: banRules[sip.MethodRegister.String()],
	}

	mgr := capture.New(cfg.Protocol, cfg.FilterPort, cfg.DeviceName, geoChecker, fw, banRules, banRuleCodes)
	wg, err := mgr.Start(ctx)
	if err != nil {
		return fmt.Errorf("启动捕获失败: %w", err)
	}

	// ctx 取消 → capture 协程退出 → wg.Wait 返回。
	wg.Wait()
	return nil
}
