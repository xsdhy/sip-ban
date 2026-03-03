// Package sip 提供SIP协议相关的解析和处理功能
package sip

import (
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"
)

// Package 表示一个SIP消息包（请求或响应）
type Package struct {
	Method         Method            // SIP方法（仅请求消息有效）
	Headers        map[string]string // SIP头部字段集合
	RequestURI     string            // 请求URI（仅请求消息有效）
	IsResponse     bool              // 是否为响应消息
	ResponseCode   int               // 响应状态码（仅响应消息有效）
	ResponseStatus string            // 响应状态描述（仅响应消息有效）
}

// DecodeFromBytes 从字节数组解析SIP消息
// 参数:
//   data - SIP消息的原始字节数据
// 返回:
//   error - 解析失败时返回错误
func (p *Package) DecodeFromBytes(data []byte) error {
	if len(data) == 0 {
		return errors.New("空消息")
	}
	p.Headers = make(map[string]string)

	var countLines int
	buffer := bytes.NewBuffer(data)

	// 逐行解析SIP消息
	for {
		line, err := buffer.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		// 去除行尾的回车换行符
		line = bytes.Trim(line, "\r\n")
		if len(line) == 0 {
			break
		}

		// 第一行是请求行或状态行
		if countLines == 0 {
			if err := p.parseFirstLine(line); err != nil {
				return err
			}
		} else {
			// 后续行是头部字段
			p.parseHeader(line)
		}
		countLines++
	}

	// 验证是否为有效的SIP消息（必须包含Call-ID）
	if p.GetCallID() == "" {
		return errors.New("不是标准的sip消息")
	}
	return nil
}

// parseFirstLine 解析SIP消息的第一行（请求行或状态行）
// 请求行格式: METHOD Request-URI SIP/2.0
// 状态行格式: SIP/2.0 Status-Code Reason-Phrase
func (p *Package) parseFirstLine(line []byte) error {
	splits := strings.SplitN(string(line), " ", 3)
	if len(splits) < 3 {
		return errors.New("invalid SIP line")
	}

	// 判断是响应还是请求
	if strings.HasPrefix(splits[0], "SIP") {
		// 响应消息: SIP/2.0 200 OK
		p.IsResponse = true
		code, err := strconv.Atoi(splits[1])
		if err != nil {
			return err
		}
		p.ResponseCode = code
		p.ResponseStatus = splits[2]
	} else {
		// 请求消息: INVITE sip:user@domain SIP/2.0
		method, err := ParseMethod(splits[0])
		if err != nil {
			return err
		}
		p.Method = method
	}
	return nil
}

// parseHeader 解析SIP头部字段
// 格式: Header-Name: Header-Value
func (p *Package) parseHeader(header []byte) {
	if len(header) == 0 {
		return
	}
	index := bytes.Index(header, []byte(":"))
	if index >= 0 {
		// 头部名称转为小写以便不区分大小写查询
		name := strings.ToLower(strings.TrimSpace(string(header[:index])))
		value := strings.TrimSpace(string(header[index+1:]))
		p.Headers[name] = value
	}
}

// GetHeader 获取指定名称的头部字段值（不区分大小写）
// 参数:
//   name - 头部字段名称
// 返回:
//   string - 头部字段值，不存在则返回空字符串
func (p *Package) GetHeader(name string) string {
	return p.Headers[strings.ToLower(name)]
}

// GetCallID 获取Call-ID头部字段值
// Call-ID是SIP消息的唯一标识符
// 返回:
//   string - Call-ID值
func (p *Package) GetCallID() string {
	return p.GetHeader("Call-ID")
}
