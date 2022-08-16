package main

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type SipPackage struct {
	Method SIPMethod

	Headers map[string]string

	// Request
	RequestURI string

	// Response
	IsResponse     bool
	ResponseCode   int
	ResponseStatus string
}

func (sip *SipPackage) DecodeFromBytes(data []byte) error {
	sip.Headers = make(map[string]string)
	// Init some vars for parsing follow-up
	var countLines int
	var line []byte
	var err error
	var offset int
	buffer := bytes.NewBuffer(data)
	for {
		// Read next line
		line, err = buffer.ReadBytes(byte('\n'))
		if err != nil {
			if err == io.EOF {
				if len(bytes.Trim(line, "\r\n")) > 0 {
					//df.SetTruncated()
				}
				break
			} else {
				return err
			}
		}
		offset += len(line)

		// Trim the new line delimiters
		line = bytes.Trim(line, "\r\n")

		// Empty line, we hit Body
		if len(line) == 0 {
			break
		}
		// First line is the SIP request/response line
		// Other lines are headers
		if countLines == 0 {
			splits := strings.SplitN(string(line), " ", 3)
			if len(splits) < 3 {
				return err
			}
			if strings.HasPrefix(splits[0], "SIP") {
				sip.IsResponse = true
				sip.ResponseCode, err = strconv.Atoi(splits[1])
				if err != nil {
					return err
				}
				sip.ResponseStatus = splits[2]
			} else {
				sip.Method, err = GetSIPMethod(splits[0])
				if err != nil {
					return err
				}
			}
		} else {
			sip.ParseHeader(line)
		}
		countLines++
	}
	return nil
}

func (s *SipPackage) ParseHeader(header []byte) {
	// Ignore empty headers
	if len(header) == 0 {
		return
	}
	// Find the ':' to separate header name and value
	index := bytes.Index(header, []byte(":"))
	if index >= 0 {
		headerName := strings.ToLower(string(bytes.Trim(header[:index], " ")))
		headerValue := string(bytes.Trim(header[index+1:], " "))
		s.Headers[headerName] = headerValue
	}
	return
}

func (s *SipPackage) GetHeader(headerName string) string {
	headerName = strings.ToLower(headerName)
	if _, ok := s.Headers[headerName]; ok {
		return s.Headers[headerName]
	}
	return ""
}

func (s *SipPackage) GetCallID() string {
	return s.GetHeader("Call-ID")
}

type SIPMethod uint16

// Here are all the SIP methods
const (
	SIPMethodInvite    SIPMethod = 1  // INVITE	[RFC3261]
	SIPMethodAck       SIPMethod = 2  // ACK	[RFC3261]
	SIPMethodBye       SIPMethod = 3  // BYE	[RFC3261]
	SIPMethodCancel    SIPMethod = 4  // CANCEL	[RFC3261]
	SIPMethodOptions   SIPMethod = 5  // OPTIONS	[RFC3261]
	SIPMethodRegister  SIPMethod = 6  // REGISTER	[RFC3261]
	SIPMethodPrack     SIPMethod = 7  // PRACK	[RFC3262]
	SIPMethodSubscribe SIPMethod = 8  // SUBSCRIBE	[RFC6665]
	SIPMethodNotify    SIPMethod = 9  // NOTIFY	[RFC6665]
	SIPMethodPublish   SIPMethod = 10 // PUBLISH	[RFC3903]
	SIPMethodInfo      SIPMethod = 11 // INFO	[RFC6086]
	SIPMethodRefer     SIPMethod = 12 // REFER	[RFC3515]
	SIPMethodMessage   SIPMethod = 13 // MESSAGE	[RFC3428]
	SIPMethodUpdate    SIPMethod = 14 // UPDATE	[RFC3311]
	SIPMethodPing      SIPMethod = 15 // PING	[https://tools.ietf.org/html/draft-fwmiller-ping-03]
)

func GetSIPMethod(method string) (SIPMethod, error) {
	switch strings.ToUpper(method) {
	case "INVITE":
		return SIPMethodInvite, nil
	case "ACK":
		return SIPMethodAck, nil
	case "BYE":
		return SIPMethodBye, nil
	case "CANCEL":
		return SIPMethodCancel, nil
	case "OPTIONS":
		return SIPMethodOptions, nil
	case "REGISTER":
		return SIPMethodRegister, nil
	case "PRACK":
		return SIPMethodPrack, nil
	case "SUBSCRIBE":
		return SIPMethodSubscribe, nil
	case "NOTIFY":
		return SIPMethodNotify, nil
	case "PUBLISH":
		return SIPMethodPublish, nil
	case "INFO":
		return SIPMethodInfo, nil
	case "REFER":
		return SIPMethodRefer, nil
	case "MESSAGE":
		return SIPMethodMessage, nil
	case "UPDATE":
		return SIPMethodUpdate, nil
	case "PING":
		return SIPMethodPing, nil
	default:
		return 0, fmt.Errorf("Unknown SIP method: '%s'", method)
	}
}

func (sm SIPMethod) String() string {
	switch sm {
	case SIPMethodInvite:
		return "INVITE"
	case SIPMethodAck:
		return "ACK"
	case SIPMethodBye:
		return "BYE"
	case SIPMethodCancel:
		return "CANCEL"
	case SIPMethodOptions:
		return "OPTIONS"
	case SIPMethodRegister:
		return "REGISTER"
	case SIPMethodPrack:
		return "PRACK"
	case SIPMethodSubscribe:
		return "SUBSCRIBE"
	case SIPMethodNotify:
		return "NOTIFY"
	case SIPMethodPublish:
		return "PUBLISH"
	case SIPMethodInfo:
		return "INFO"
	case SIPMethodRefer:
		return "REFER"
	case SIPMethodMessage:
		return "MESSAGE"
	case SIPMethodUpdate:
		return "UPDATE"
	case SIPMethodPing:
		return "PING"
	default:
		return "Unknown"
	}
}
