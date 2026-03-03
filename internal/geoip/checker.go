// Package geoip 提供IP地理位置查询功能
package geoip

import "github.com/ipipdotnet/ipdb-go"

// Checker IP地理位置检查器
type Checker struct {
	db *ipdb.City // IP数据库实例
}

// New 创建一个新的IP地理位置检查器
// 参数:
//   dbPath - IP数据库文件路径
// 返回:
//   *Checker - 检查器实例
//   error - 数据库加载失败时返回错误
func New(dbPath string) (*Checker, error) {
	db, err := ipdb.NewCity(dbPath)
	if err != nil {
		return nil, err
	}
	return &Checker{db: db}, nil
}

// IsChina 检查IP地址是否属于中国
// 参数:
//   ip - 要检查的IP地址字符串
// 返回:
//   bool - true表示是中国IP或局域网IP，false表示非中国IP
//   string - 国家/地区名称
func (c *Checker) IsChina(ip string) (bool, string) {
	if c.db == nil {
		return true, ""
	}

	info, err := c.db.FindInfo(ip, "CN")
	if err != nil {
		// 查询失败时默认放行
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
