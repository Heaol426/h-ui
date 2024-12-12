package service

import (
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"h-ui/dao"
	"h-ui/model/bo"
	"h-ui/model/constant"
	"h-ui/proxy"
	"net/url"
	"strings"
	"time"
)

func Hysteria2Auth(conPass string) (int64, string, error) {
	if !Hysteria2IsRunning() {
		return 0, "", errors.New("hysteria2 is not running")
	}

	now := time.Now().UnixMilli()
	account, err := dao.GetAccount("con_pass = ? and deleted = 0 and (quota < 0 or quota > download + upload) and ? < expire_time and ? > kick_util_time", conPass, now, now)
	if err != nil {
		return 0, "", err
	}

	// 限制设备数
	onlineUsers, err := Hysteria2Online()
	if err != nil {
		return 0, "", err
	}
	device, exist := onlineUsers[*account.Username]
	if exist && *account.DeviceNo <= device {
		return 0, "", errors.New("device limited")
	}

	return *account.Id, *account.Username, nil
}

func Hysteria2Online() (map[string]int64, error) {
	if !Hysteria2IsRunning() {
		return map[string]int64{}, nil
	}
	apiPort, err := GetHysteria2ApiPort()
	if err != nil {
		return nil, errors.New("get hysteria2 apiPort err")
	}
	jwtSecretConfig, err := dao.GetConfig("key = ?", constant.JwtSecret)
	if err != nil {
		return nil, err
	}
	onlineUsers, err := proxy.NewHysteria2Api(apiPort).OnlineUsers(*jwtSecretConfig.Value)
	if err != nil {
		return nil, err
	}
	return onlineUsers, nil
}

func Hysteria2Kick(ids []int64, kickUtilTime int64) error {
	if !Hysteria2IsRunning() {
		return errors.New("hysteria2 is not running")
	}
	if err := dao.UpdateAccount(ids, map[string]interface{}{"kick_util_time": kickUtilTime}); err != nil {
		return err
	}

	accounts, err := dao.ListAccount("id in ?", ids)
	if err != nil {
		return err
	}
	var keys []string
	for _, item := range accounts {
		keys = append(keys, *item.Username)
	}
	apiPort, err := GetHysteria2ApiPort()
	if err != nil {
		return errors.New("get hysteria2 apiPort err")
	}
	jwtSecretConfig, err := dao.GetConfig("key = ?", constant.JwtSecret)
	if err != nil {
		return err
	}
	if err = proxy.NewHysteria2Api(apiPort).KickUsers(keys, *jwtSecretConfig.Value); err != nil {
		return err
	}
	return nil
}

// Hysteria2SubscribeUrl 生成指定账户的 Hysteria2 订阅 URL。
// 参数:
//
//	accountId - 账户 ID，用于查询账户信息。
//	protocol - 网络协议，用于构造订阅 URL 的协议头。
//	host - 主机名，用于构造订阅 URL 的主机部分。
//
// 返回值:
//
//	生成的订阅 URL 字符串。
//	可能发生的错误。
func Hysteria2SubscribeUrl(accountId int64, protocol string, host string) (string, error) {
	// 根据账户 ID 查询账户信息。
	account, err := dao.GetAccount("id = ?", accountId)
	if err != nil {
		// 如果查询账户时发生错误，返回空字符串和错误。
		return "", err
	}
	// 使用查询到的账户信息和提供的协议、主机名构造订阅 URL。
	return fmt.Sprintf("%s//%s/hui/%s", protocol, host, *account.ConPass), nil
}

/*func Hysteria2Subscribe(conPass string, clientType string, host string) (string, string, error) {
	hysteria2Config, err := GetHysteria2Config()
	if err != nil {
		return "", "", err
	}
	if hysteria2Config.Listen == nil || *hysteria2Config.Listen == "" {
		return "", "", errors.New("hysteria2 config is empty")
	}

	account, err := dao.GetAccount("con_pass = ?", conPass)
	if err != nil {
		return "", "", err
	}

	hysteria2Name := "hysteria2"
	hysteria2ConfigRemark, err := dao.GetConfig("key = ?", constant.Hysteria2ConfigRemark)
	if err != nil {
		return "", "", err
	}
	if *hysteria2ConfigRemark.Value != "" {
		hysteria2Name = *hysteria2ConfigRemark.Value
	}

	hysteria2ConfigPortHopping, err := dao.GetConfig("key = ?", constant.Hysteria2ConfigPortHopping)
	if err != nil {
		return "", "", err
	}

	userInfo := ""
	configYaml := ""
	if clientType == constant.Shadowrocket || clientType == constant.Clash {
		userInfo = fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d",
			*account.Upload,
			*account.Download,
			*account.Quota,
			*account.ExpireTime/1000)

		hysteria2 := bo.Hysteria2{
			Name:     hysteria2Name,
			Type:     "hysteria2",
			Server:   strings.Split(host, ":")[0],
			Port:     strings.Split(*hysteria2Config.Listen, ":")[1],
			Ports:    *hysteria2ConfigPortHopping.Value,
			Password: conPass,
		}

		if hysteria2Config.Bandwidth != nil {
			if hysteria2Config.Bandwidth.Up != nil &&
				*hysteria2Config.Bandwidth.Up != "" {
				hysteria2.Up = *hysteria2Config.Bandwidth.Up
			}
			if hysteria2Config.Bandwidth.Down != nil &&
				*hysteria2Config.Bandwidth.Down != "" {
				hysteria2.Down = *hysteria2Config.Bandwidth.Down
			}
		}

		if hysteria2Config.Obfs != nil &&
			hysteria2Config.Obfs.Type != nil &&
			*hysteria2Config.Obfs.Type == "salamander" &&
			hysteria2Config.Obfs.Salamander != nil &&
			hysteria2Config.Obfs.Salamander.Password != nil &&
			*hysteria2Config.Obfs.Salamander.Password != "" {
			hysteria2.Obfs = "salamander"
			hysteria2.ObfsPassword = *hysteria2Config.Obfs.Salamander.Password
		}

		if hysteria2Config.ACME != nil &&
			hysteria2Config.ACME.Domains != nil &&
			len(hysteria2Config.ACME.Domains) > 0 {
			hysteria2.Sni = hysteria2Config.ACME.Domains[0]
		}

		if hysteria2Config.TLS != nil &&
			hysteria2Config.TLS.Cert != nil &&
			*hysteria2Config.TLS.Cert != "" &&
			hysteria2Config.TLS.Key != nil &&
			*hysteria2Config.TLS.Key != "" {
			hysteria2.SkipCertVerify = true
		}

		proxyGroup := bo.ProxyGroup{
			Name:    "PROXY",
			Type:    "select",
			Proxies: []string{hysteria2Name},
		}

		clashConfig := bo.ClashConfig{
			ProxyGroups: []bo.ProxyGroup{
				proxyGroup,
			},
			Proxies: []interface{}{hysteria2},
		}
		clashConfigYaml, err := yaml.Marshal(&clashConfig)
		if err != nil {
			return "", "", err
		}
		configYaml = string(clashConfigYaml)
	}

	return userInfo, configYaml, nil
}
*/

// Hysteria2Subscribe 函数用于生成Hysteria2的订阅配置。
// 参数 conPass 是用户的连接密码，clientType 是客户端类型，host 是服务主机地址。
// 返回值是用户信息字符串，配置的YAML字符串和可能的错误。
func Hysteria2Subscribe(conPass string, clientType string, host string) (string, string, error) {
	// 获取Hysteria2配置
	hysteria2Config, err := GetHysteria2Config()
	if err != nil {
		return "", "", err
	}
	// 检查Hysteria2配置是否为空
	if hysteria2Config.Listen == nil || *hysteria2Config.Listen == "" {
		return "", "", errors.New("hysteria2 config is empty")
	}

	// 根据连接密码获取用户账户信息
	account, err := dao.GetAccount("con_pass = ?", conPass)
	if err != nil {
		return "", "", err
	}

	// 设置Hysteria2服务名称
	hysteria2Name := "hysteria2"
	// 尝试获取Hysteria2配置的备注信息以定制服务名称
	hysteria2ConfigRemark, err := dao.GetConfig("key = ?", constant.Hysteria2ConfigRemark)
	if err != nil {
		return "", "", err
	}
	if *hysteria2ConfigRemark.Value != "" {
		hysteria2Name = *hysteria2ConfigRemark.Value
	}

	// 获取Hysteria2配置的端口跳跃设置
	hysteria2ConfigPortHopping, err := dao.GetConfig("key = ?", constant.Hysteria2ConfigPortHopping)
	if err != nil {
		return "", "", err
	}

	// 初始化用户信息和配置YAML字符串
	userInfo := ""
	configYaml := ""
	// 根据客户端类型生成相应的配置
	if clientType == constant.Shadowrocket || clientType == constant.Clash {
		// 生成用户信息字符串
		userInfo = fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d",
			*account.Upload,
			*account.Download,
			*account.Quota,
			*account.ExpireTime/1000)

		// 初始化Hysteria2配置对象
		hysteria2 := bo.Hysteria2{
			Name:     hysteria2Name,
			Type:     "hysteria2",
			Server:   strings.Split(host, ":")[0],
			Port:     strings.Split(*hysteria2Config.Listen, ":")[1],
			Ports:    *hysteria2ConfigPortHopping.Value,
			Password: conPass,
		}

		// 生成IPv4和IPv6的Hysteria2配置对象
		ip4 := bo.Hysteria2{
			Name:   "IPv4",
			Type:   "hysteria2",
			Server: "ip4.ioeah.top",
			//Server:   "ip4.dycloud.buzz",
			Port:     strings.Split(*hysteria2Config.Listen, ":")[1],
			Ports:    *hysteria2ConfigPortHopping.Value,
			Password: conPass,
		}
		ip6 := bo.Hysteria2{
			Name:   "IPv6",
			Type:   "hysteria2",
			Server: "ip6.ioeah.top",
			//Server:   "ip6.dycloud.buzz",
			Port:     strings.Split(*hysteria2Config.Listen, ":")[1],
			Ports:    *hysteria2ConfigPortHopping.Value,
			Password: conPass,
		}

		/*bilibili := bo.Hysteria2{
			Name:     "Bilibili",
			Type:     "hysteria2",
			Server:   strings.Split(host, ":")[0],
			Port:     strings.Split(*hysteria2Config.Listen, ":")[1],
			Ports:    *hysteria2ConfigPortHopping.Value,
			Password: conPass,
		}*/

		// 设置上传和下载带宽限制
		if hysteria2Config.Bandwidth != nil {
			if hysteria2Config.Bandwidth.Up != nil &&
				*hysteria2Config.Bandwidth.Up != "" {
				hysteria2.Up = *hysteria2Config.Bandwidth.Up
				ip4.Up = *hysteria2Config.Bandwidth.Up
				ip6.Up = *hysteria2Config.Bandwidth.Up
			}
			if hysteria2Config.Bandwidth.Down != nil &&
				*hysteria2Config.Bandwidth.Down != "" {
				hysteria2.Down = *hysteria2Config.Bandwidth.Down
				ip4.Down = *hysteria2Config.Bandwidth.Down
				ip6.Down = *hysteria2Config.Bandwidth.Down
			}
		}

		// 配置混淆（Obfuscation）设置
		if hysteria2Config.Obfs != nil &&
			hysteria2Config.Obfs.Type != nil &&
			*hysteria2Config.Obfs.Type == "salamander" &&
			hysteria2Config.Obfs.Salamander != nil &&
			hysteria2Config.Obfs.Salamander.Password != nil &&
			*hysteria2Config.Obfs.Salamander.Password != "" {
			hysteria2.Obfs = "salamander"
			hysteria2.ObfsPassword = *hysteria2Config.Obfs.Salamander.Password
			ip4.Obfs = "salamander"
			ip4.ObfsPassword = *hysteria2Config.Obfs.Salamander.Password
			ip6.Obfs = "salamander"
			ip6.ObfsPassword = *hysteria2Config.Obfs.Salamander.Password
		}

		// 设置SNI（Server Name Indication）信息
		if hysteria2Config.ACME != nil &&
			hysteria2Config.ACME.Domains != nil &&
			len(hysteria2Config.ACME.Domains) > 0 {
			hysteria2.Sni = hysteria2Config.ACME.Domains[0]
			ip4.Sni = hysteria2Config.ACME.Domains[0]
			ip6.Sni = hysteria2Config.ACME.Domains[0]
		}

		// 配置TLS证书验证
		if hysteria2Config.TLS != nil &&
			hysteria2Config.TLS.Cert != nil &&
			*hysteria2Config.TLS.Cert != "" &&
			hysteria2Config.TLS.Key != nil &&
			*hysteria2Config.TLS.Key != "" {
			hysteria2.SkipCertVerify = true
			ip4.SkipCertVerify = true
			ip6.SkipCertVerify = true
		}

		// 初始化代理组
		proxyGroup := bo.ProxyGroup{
			Name: "PROXY",
			Type: "select",
			Proxies: []string{
				hysteria2Name,
				ip4.Name,
				ip6.Name,
				"DIRECT",
			},
		}

		// 初始化Bilibili代理组
		biliProxyGroup := bo.ProxyGroup{
			Name: "Bilibili",
			Type: "select",
			Proxies: []string{
				"DIRECT",
				hysteria2Name,
			},
		}

		// 定义规则列表
		rules := []string{
			"DOMAIN-SUFFIX, bilibili.com, Bilibili",
			"DOMAIN-SUFFIX, hdslb.com, Bilibili",
			"DOMAIN-SUFFIX, bilivideo.cn, Bilibili",
			"DOMAIN-SUFFIX, biliapi.net, Bilibili",
			"DOMAIN-SUFFIX, biliapi.com, Bilibili",
			"DOMAIN-SUFFIX, biliimg.com, Bilibili",
			"DOMAIN-SUFFIX, bilivideo.com, Bilibili",
			"DOMAIN-SUFFIX, h2.smtcdns.net, Bilibili",
			"DOMAIN-SUFFIX, steampowered.com, PROXY",
			"DOMAIN-SUFFIX, steamcommunity.com, PROXY",
			"DOMAIN-SUFFIX, steamstatic.com, PROXY",
			"DOMAIN-SUFFIX, steam-chat.com, PROXY",
			"DOMAIN-SUFFIX, steamserver.net, DIRECT",
			"DOMAIN-SUFFIX, steamcontent.com, DIRECT",
			"IP-CIDR, 127.0.0.0/8, DIRECT",
			"IP-CIDR, 10.0.0.0/8, DIRECT",
			"IP-CIDR, 172.16.0.0/12, DIRECT",
			"IP-CIDR, 192.168.0.0/16, DIRECT",
			"IP-CIDR, 17.0.0.0/8, DIRECT",
			"IP-CIDR, 100.64.0.0/10, DIRECT",
			"IP-CIDR, 224.0.0.0/4, DIRECT",
			"IP-CIDR6, fe80::/10, DIRECT",
			"GEOIP, CN, DIRECT",
			"MATCH, PROXY",
		}

		// 初始化Clash配置
		clashConfig := bo.ClashConfig{
			ProxyGroups: []bo.ProxyGroup{
				proxyGroup,
				biliProxyGroup,
			},
			Proxies: []interface{}{hysteria2, ip4, ip6},
			Rules:   rules,
		}

		// 将Clash配置编码为YAML字符串
		clashConfigYaml, err := yaml.Marshal(&clashConfig)
		if err != nil {
			return "", "", err
		}
		configYaml = string(clashConfigYaml)
	}

	// 返回用户信息和配置YAML字符串
	return userInfo, configYaml, nil
}

// Hysteria2Url 生成 Hysteria2 协议的 URL。
// 接收 accountId 以获取账户信息，hostname 作为 URL 的一部分。
// 返回生成的 Hysteria2 URL 字符串和错误信息（如果有）。
func Hysteria2Url(accountId int64, hostname string) (string, error) {
	// 获取 Hysteria2 配置，如果获取失败或配置为空，则返回错误。
	hysteria2Config, err := GetHysteria2Config()
	if err != nil {
		return "", err
	}
	if hysteria2Config.Listen == nil || *hysteria2Config.Listen == "" {
		return "", errors.New("hysteria2 config is empty")
	}

	// 根据 accountId 获取账户信息，如果获取失败，则返回错误。
	account, err := dao.GetAccount("id = ?", accountId)
	if err != nil {
		return "", err
	}

	// 初始化 URL 配置字符串。根据 Hysteria2 配置中的 Obfs 设置，如果匹配特定条件，则添加 Obfs 相关的配置到 URL。
	urlConfig := ""
	if hysteria2Config.Obfs != nil &&
		hysteria2Config.Obfs.Type != nil &&
		*hysteria2Config.Obfs.Type == "salamander" &&
		hysteria2Config.Obfs.Salamander != nil &&
		hysteria2Config.Obfs.Salamander.Password != nil &&
		*hysteria2Config.Obfs.Salamander.Password != "" {
		urlConfig += fmt.Sprintf("&obfs=salamander&obfs-password=%s", *hysteria2Config.Obfs.Salamander.Password)
	}

	// 如果 Hysteria2 配置中有 ACME 设置且至少有一个域名，则添加 SNI 和 Peer 相关的配置到 URL。
	if hysteria2Config.ACME != nil &&
		hysteria2Config.ACME.Domains != nil &&
		len(hysteria2Config.ACME.Domains) > 0 {
		urlConfig += fmt.Sprintf("&sni=%s", hysteria2Config.ACME.Domains[0])
		// shadowrocket
		urlConfig += fmt.Sprintf("&peer=%s", hysteria2Config.ACME.Domains[0])
	}

	// 设置 insecure 标志为 0，如果配置了 TLS 证书和密钥，则可以设置 insecure 为 1，但当前代码中此部分被注释掉了。
	var insecure int64 = 0
	//if hysteria2Config.TLS != nil &&
	//    hysteria2Config.TLS.Cert != nil &&
	//    *hysteria2Config.TLS.Cert != "" &&
	//    hysteria2Config.TLS.Key != nil &&
	//    *hysteria2Config.TLS.Key != "" {
	//    insecure = 1
	//}
	urlConfig += fmt.Sprintf("&insecure=%d", insecure)

	// 如果配置了带宽限制，则添加下行带宽限制到 URL 配置中。
	if hysteria2Config.Bandwidth != nil &&
		hysteria2Config.Bandwidth.Down != nil &&
		*hysteria2Config.Bandwidth.Down != "" {
		// shadowrocket
		urlConfig += fmt.Sprintf("&downmbps=%s", url.PathEscape(*hysteria2Config.Bandwidth.Down))
	}

	// 获取并添加端口跳跃配置到 URL，如果配置存在且不为空。
	hysteria2ConfigPortHopping, err := dao.GetConfig("key = ?", constant.Hysteria2ConfigPortHopping)
	if err != nil {
		return "", err
	}
	if *hysteria2ConfigPortHopping.Value != "" {
		// shadowrocket
		urlConfig += fmt.Sprintf("&mport=%s", *hysteria2ConfigPortHopping.Value)
	}

	// 获取并添加备注配置到 URL，如果配置存在且不为空。
	hysteria2ConfigRemark, err := dao.GetConfig("key = ?", constant.Hysteria2ConfigRemark)
	if err != nil {
		return "", err
	}
	if *hysteria2ConfigRemark.Value != "" {
		urlConfig += fmt.Sprintf("#%s", *hysteria2ConfigRemark.Value)
	}

	// 如果 urlConfig 不为空，则移除开头的 "&" 并作为查询参数的一部分。
	if urlConfig != "" {
		urlConfig = "/?" + strings.TrimPrefix(urlConfig, "&")
	}

	// 组合所有部分生成最终的 Hysteria2 URL，并返回。
	return fmt.Sprintf("hysteria2://%s@%s%s", *account.ConPass, hostname, *hysteria2Config.Listen) + urlConfig, nil
}
