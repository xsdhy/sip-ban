// Package sip 提供SIP协议相关的解析和处理功能
package sip

import (
	"fmt"
	"strings"
)

// Method 表示SIP方法类型
type Method uint16

// SIP方法常量定义
// 参考 RFC 3261 和相关扩展RFC
const (
	MethodInvite    Method = 1  // INVITE - 发起会话邀请
	MethodAck       Method = 2  // ACK - 确认请求
	MethodBye       Method = 3  // BYE - 终止会话
	MethodCancel    Method = 4  // CANCEL - 取消请求
	MethodOptions   Method = 5  // OPTIONS - 查询服务器能力
	MethodRegister  Method = 6  // REGISTER - 注册用户代理
	MethodPrack     Method = 7  // PRACK - 临时响应确认
	MethodSubscribe Method = 8  // SUBSCRIBE - 订阅事件通知
	MethodNotify    Method = 9  // NOTIFY - 事件通知
	MethodPublish   Method = 10 // PUBLISH - 发布状态信息
	MethodInfo      Method = 11 // INFO - 会话中信息传递
	MethodRefer     Method = 12 // REFER - 呼叫转移
	MethodMessage   Method = 13 // MESSAGE - 即时消息
	MethodUpdate    Method = 14 // UPDATE - 更新会话参数
	MethodPing      Method = 15 // PING - 保活检测
)

// ParseMethod 将字符串形式的SIP方法名解析为Method类型
// 参数:
//   method - SIP方法名字符串（不区分大小写）
// 返回:
//   Method - 解析后的方法类型
//   error - 如果方法名未知则返回错误
func ParseMethod(method string) (Method, error) {
	switch strings.ToUpper(method) {
	case "INVITE":
		return MethodInvite, nil
	case "ACK":
		return MethodAck, nil
	case "BYE":
		return MethodBye, nil
	case "CANCEL":
		return MethodCancel, nil
	case "OPTIONS":
		return MethodOptions, nil
	case "REGISTER":
		return MethodRegister, nil
	case "PRACK":
		return MethodPrack, nil
	case "SUBSCRIBE":
		return MethodSubscribe, nil
	case "NOTIFY":
		return MethodNotify, nil
	case "PUBLISH":
		return MethodPublish, nil
	case "INFO":
		return MethodInfo, nil
	case "REFER":
		return MethodRefer, nil
	case "MESSAGE":
		return MethodMessage, nil
	case "UPDATE":
		return MethodUpdate, nil
	case "PING":
		return MethodPing, nil
	default:
		return 0, fmt.Errorf("unknown SIP method: '%s'", method)
	}
}

// String 将Method类型转换为字符串表示
// 返回SIP方法的标准名称（大写）
func (m Method) String() string {
	switch m {
	case MethodInvite:
		return "INVITE"
	case MethodAck:
		return "ACK"
	case MethodBye:
		return "BYE"
	case MethodCancel:
		return "CANCEL"
	case MethodOptions:
		return "OPTIONS"
	case MethodRegister:
		return "REGISTER"
	case MethodPrack:
		return "PRACK"
	case MethodSubscribe:
		return "SUBSCRIBE"
	case MethodNotify:
		return "NOTIFY"
	case MethodPublish:
		return "PUBLISH"
	case MethodInfo:
		return "INFO"
	case MethodRefer:
		return "REFER"
	case MethodMessage:
		return "MESSAGE"
	case MethodUpdate:
		return "UPDATE"
	case MethodPing:
		return "PING"
	default:
		return "Unknown"
	}
}
