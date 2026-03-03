package sip

import (
	"testing"
)

// TestParseMethod 测试SIP方法解析功能
func TestParseMethod(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Method
		wantErr bool
	}{
		{"INVITE大写", "INVITE", MethodInvite, false},
		{"invite小写", "invite", MethodInvite, false},
		{"Invite混合", "Invite", MethodInvite, false},
		{"ACK", "ACK", MethodAck, false},
		{"BYE", "BYE", MethodBye, false},
		{"CANCEL", "CANCEL", MethodCancel, false},
		{"OPTIONS", "OPTIONS", MethodOptions, false},
		{"REGISTER", "REGISTER", MethodRegister, false},
		{"PRACK", "PRACK", MethodPrack, false},
		{"SUBSCRIBE", "SUBSCRIBE", MethodSubscribe, false},
		{"NOTIFY", "NOTIFY", MethodNotify, false},
		{"PUBLISH", "PUBLISH", MethodPublish, false},
		{"INFO", "INFO", MethodInfo, false},
		{"REFER", "REFER", MethodRefer, false},
		{"MESSAGE", "MESSAGE", MethodMessage, false},
		{"UPDATE", "UPDATE", MethodUpdate, false},
		{"PING", "PING", MethodPing, false},
		{"未知方法", "UNKNOWN", 0, true},
		{"空字符串", "", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseMethod(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseMethod() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseMethod() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestMethodString 测试Method类型转字符串功能
func TestMethodString(t *testing.T) {
	tests := []struct {
		name   string
		method Method
		want   string
	}{
		{"INVITE", MethodInvite, "INVITE"},
		{"ACK", MethodAck, "ACK"},
		{"BYE", MethodBye, "BYE"},
		{"CANCEL", MethodCancel, "CANCEL"},
		{"OPTIONS", MethodOptions, "OPTIONS"},
		{"REGISTER", MethodRegister, "REGISTER"},
		{"PRACK", MethodPrack, "PRACK"},
		{"SUBSCRIBE", MethodSubscribe, "SUBSCRIBE"},
		{"NOTIFY", MethodNotify, "NOTIFY"},
		{"PUBLISH", MethodPublish, "PUBLISH"},
		{"INFO", MethodInfo, "INFO"},
		{"REFER", MethodRefer, "REFER"},
		{"MESSAGE", MethodMessage, "MESSAGE"},
		{"UPDATE", MethodUpdate, "UPDATE"},
		{"PING", MethodPing, "PING"},
		{"未知", Method(999), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.method.String(); got != tt.want {
				t.Errorf("Method.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestParseMethodRoundTrip 测试解析和转字符串的往返转换
func TestParseMethodRoundTrip(t *testing.T) {
	methods := []string{"INVITE", "ACK", "BYE", "CANCEL", "OPTIONS", "REGISTER"}

	for _, methodStr := range methods {
		t.Run(methodStr, func(t *testing.T) {
			method, err := ParseMethod(methodStr)
			if err != nil {
				t.Fatalf("ParseMethod() error = %v", err)
			}

			got := method.String()
			if got != methodStr {
				t.Errorf("往返转换失败: 输入 %s, 输出 %s", methodStr, got)
			}
		})
	}
}
