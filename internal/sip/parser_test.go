package sip

import (
	"testing"
)

// TestPackageDecodeFromBytes_Request 测试解析SIP请求消息
func TestPackageDecodeFromBytes_Request(t *testing.T) {
	// 构造一个标准的SIP INVITE请求
	sipRequest := `INVITE sip:bob@example.com SIP/2.0
Via: SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776asdhds
Max-Forwards: 70
To: Bob <sip:bob@example.com>
From: Alice <sip:alice@example.com>;tag=1928301774
Call-ID: a84b4c76e66710@pc33.example.com
CSeq: 314159 INVITE
Contact: <sip:alice@pc33.example.com>
Content-Type: application/sdp
Content-Length: 142

`

	pkg := &Package{}
	err := pkg.DecodeFromBytes([]byte(sipRequest))
	if err != nil {
		t.Fatalf("DecodeFromBytes() error = %v", err)
	}

	// 验证解析结果
	if pkg.IsResponse {
		t.Error("IsResponse应该为false")
	}

	if pkg.Method != MethodInvite {
		t.Errorf("Method = %v, want %v", pkg.Method, MethodInvite)
	}

	if pkg.GetCallID() != "a84b4c76e66710@pc33.example.com" {
		t.Errorf("Call-ID = %v, want a84b4c76e66710@pc33.example.com", pkg.GetCallID())
	}

	if pkg.GetHeader("From") != "Alice <sip:alice@example.com>;tag=1928301774" {
		t.Errorf("From header不匹配")
	}

	if pkg.GetHeader("Content-Type") != "application/sdp" {
		t.Errorf("Content-Type = %v, want application/sdp", pkg.GetHeader("Content-Type"))
	}
}

// TestPackageDecodeFromBytes_Response 测试解析SIP响应消息
func TestPackageDecodeFromBytes_Response(t *testing.T) {
	// 构造一个SIP 200 OK响应
	sipResponse := `SIP/2.0 200 OK
Via: SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776asdhds
To: Bob <sip:bob@example.com>;tag=a6c85cf
From: Alice <sip:alice@example.com>;tag=1928301774
Call-ID: a84b4c76e66710@pc33.example.com
CSeq: 314159 INVITE
Contact: <sip:bob@192.0.2.4>
Content-Type: application/sdp
Content-Length: 131

`

	pkg := &Package{}
	err := pkg.DecodeFromBytes([]byte(sipResponse))
	if err != nil {
		t.Fatalf("DecodeFromBytes() error = %v", err)
	}

	// 验证解析结果
	if !pkg.IsResponse {
		t.Error("IsResponse应该为true")
	}

	if pkg.ResponseCode != 200 {
		t.Errorf("ResponseCode = %v, want 200", pkg.ResponseCode)
	}

	if pkg.ResponseStatus != "OK" {
		t.Errorf("ResponseStatus = %v, want OK", pkg.ResponseStatus)
	}

	if pkg.GetCallID() != "a84b4c76e66710@pc33.example.com" {
		t.Errorf("Call-ID不匹配")
	}
}

// TestPackageDecodeFromBytes_ErrorCases 测试错误情况
func TestPackageDecodeFromBytes_ErrorCases(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "空消息",
			input:   []byte(""),
			wantErr: true,
		},
		{
			name:    "缺少Call-ID",
			input:   []byte("INVITE sip:bob@example.com SIP/2.0\r\nFrom: Alice\r\n\r\n"),
			wantErr: true,
		},
		{
			name:    "无效的第一行",
			input:   []byte("INVALID\r\nCall-ID: test\r\n\r\n"),
			wantErr: true,
		},
		{
			name:    "无效的响应码",
			input:   []byte("SIP/2.0 ABC OK\r\nCall-ID: test\r\n\r\n"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg := &Package{}
			err := pkg.DecodeFromBytes(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeFromBytes() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestPackageGetHeader 测试头部字段获取（不区分大小写）
func TestPackageGetHeader(t *testing.T) {
	sipMsg := `INVITE sip:bob@example.com SIP/2.0
Call-ID: test123
Content-Type: application/sdp
From: Alice

`

	pkg := &Package{}
	err := pkg.DecodeFromBytes([]byte(sipMsg))
	if err != nil {
		t.Fatalf("DecodeFromBytes() error = %v", err)
	}

	tests := []struct {
		name   string
		header string
		want   string
	}{
		{"小写", "call-id", "test123"},
		{"大写", "CALL-ID", "test123"},
		{"混合", "Call-ID", "test123"},
		{"Content-Type小写", "content-type", "application/sdp"},
		{"不存在的头部", "X-Custom", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pkg.GetHeader(tt.header)
			if got != tt.want {
				t.Errorf("GetHeader(%s) = %v, want %v", tt.header, got, tt.want)
			}
		})
	}
}

// TestPackageDecodeFromBytes_MultipleHeaders 测试多个头部字段
func TestPackageDecodeFromBytes_MultipleHeaders(t *testing.T) {
	sipMsg := `REGISTER sip:example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.1.100:5060
From: <sip:user@example.com>;tag=abc123
To: <sip:user@example.com>
Call-ID: unique-call-id-12345
CSeq: 1 REGISTER
Contact: <sip:user@192.168.1.100:5060>
Expires: 3600
User-Agent: SIP-Ban-Test/1.0

`

	pkg := &Package{}
	err := pkg.DecodeFromBytes([]byte(sipMsg))
	if err != nil {
		t.Fatalf("DecodeFromBytes() error = %v", err)
	}

	if pkg.Method != MethodRegister {
		t.Errorf("Method = %v, want REGISTER", pkg.Method)
	}

	// 验证所有头部字段都被正确解析
	expectedHeaders := map[string]string{
		"via":        "SIP/2.0/UDP 192.168.1.100:5060",
		"from":       "<sip:user@example.com>;tag=abc123",
		"to":         "<sip:user@example.com>",
		"call-id":    "unique-call-id-12345",
		"cseq":       "1 REGISTER",
		"contact":    "<sip:user@192.168.1.100:5060>",
		"expires":    "3600",
		"user-agent": "SIP-Ban-Test/1.0",
	}

	for header, expected := range expectedHeaders {
		got := pkg.GetHeader(header)
		if got != expected {
			t.Errorf("Header %s = %v, want %v", header, got, expected)
		}
	}
}

// TestPackageDecodeFromBytes_401Response 测试401响应（常见的认证失败响应）
func TestPackageDecodeFromBytes_401Response(t *testing.T) {
	sipResponse := `SIP/2.0 401 Unauthorized
Via: SIP/2.0/UDP 192.168.1.100:5060
From: <sip:user@example.com>;tag=abc123
To: <sip:user@example.com>;tag=server123
Call-ID: test-401-response
CSeq: 1 REGISTER
WWW-Authenticate: Digest realm="example.com"

`

	pkg := &Package{}
	err := pkg.DecodeFromBytes([]byte(sipResponse))
	if err != nil {
		t.Fatalf("DecodeFromBytes() error = %v", err)
	}

	if !pkg.IsResponse {
		t.Error("应该是响应消息")
	}

	if pkg.ResponseCode != 401 {
		t.Errorf("ResponseCode = %v, want 401", pkg.ResponseCode)
	}

	if pkg.ResponseStatus != "Unauthorized" {
		t.Errorf("ResponseStatus = %v, want Unauthorized", pkg.ResponseStatus)
	}

	if pkg.GetHeader("WWW-Authenticate") != `Digest realm="example.com"` {
		t.Errorf("WWW-Authenticate header不匹配")
	}
}
