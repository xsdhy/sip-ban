package main

import (
	"github.com/ipipdotnet/ipdb-go"
)

var IPDB *ipdb.City

func checkIpInCN(ip string) (bool, string) {
	if IPDB == nil {
		return true, ""
	}
	info, err := IPDB.FindInfo(ip, "CN")
	if err != nil {
		return true, ""
	}
	switch info.CountryName {
	case "局域网", "本机地址":
		return true, "局域网"
	case "中国":
		return true, "中国"
	default:
		return false, info.CountryName
	}
}
