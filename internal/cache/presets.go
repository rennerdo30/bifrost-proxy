package cache

import (
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/matcher"
)

// PresetName is the identifier for a built-in cache preset.
type PresetName string

const (
	PresetSteam       PresetName = "steam"
	PresetOrigin      PresetName = "origin"
	PresetEpic        PresetName = "epic"
	PresetBattleNet   PresetName = "battlenet"
	PresetWindows     PresetName = "windows"
	PresetPlayStation PresetName = "playstation"
	PresetXbox        PresetName = "xbox"
	PresetNintendo    PresetName = "nintendo"
	PresetUbisoft     PresetName = "ubisoft"
	PresetRiot        PresetName = "riot"
	PresetApple       PresetName = "apple"
	PresetGoogle      PresetName = "google"
	PresetLinux       PresetName = "linux"
)

// Preset defines a built-in cache rule preset.
type Preset struct {
	Name        PresetName
	Description string
	Domains     []string
	TTL         time.Duration
	Priority    int
}

// presets contains all built-in presets.
var presets = map[PresetName]Preset{
	PresetSteam: {
		Name:        PresetSteam,
		Description: "Steam game downloads and updates",
		Domains: []string{
			"*.steamcontent.com",
			"content*.steampowered.com",
			"*.cs.steampowered.com",
			"steamcdn-*.akamaihd.net",
			"content*.steamcontent.com",
			"clientconfig.akamai.steamstatic.com",
		},
		TTL:      365 * 24 * time.Hour, // 1 year
		Priority: 100,
	},

	PresetOrigin: {
		Name:        PresetOrigin,
		Description: "EA Origin/EA App game downloads",
		Domains: []string{
			"origin-a.akamaihd.net",
			"*.akamaized.net",
			"lvlt.cdn.ea.com",
			"cdn.ea.com",
			"*.cdn.ea.com",
		},
		TTL:      365 * 24 * time.Hour,
		Priority: 100,
	},

	PresetEpic: {
		Name:        PresetEpic,
		Description: "Epic Games Store downloads",
		Domains: []string{
			"*.epicgames.com",
			"download*.epicgames.com",
			"epicgames-download1.akamaized.net",
			"fastly-download.epicgames.com",
			"cdn1.epicgames.com",
			"cdn2.epicgames.com",
		},
		TTL:      365 * 24 * time.Hour,
		Priority: 100,
	},

	PresetBattleNet: {
		Name:        PresetBattleNet,
		Description: "Blizzard Battle.net game downloads",
		Domains: []string{
			"*.blizzard.com",
			"*.battle.net",
			"blzddist*.akamaihd.net",
			"level3.blizzard.com",
			"dist.blizzard.com",
			"*.dist.blizzard.com",
		},
		TTL:      365 * 24 * time.Hour,
		Priority: 100,
	},

	PresetWindows: {
		Name:        PresetWindows,
		Description: "Windows Update and Microsoft downloads",
		Domains: []string{
			"*.windowsupdate.com",
			"*.download.microsoft.com",
			"*.dl.delivery.mp.microsoft.com",
			"*.update.microsoft.com",
			"dl.delivery.mp.microsoft.com",
			"*.delivery.mp.microsoft.com",
			"tlu.dl.delivery.mp.microsoft.com",
			"*.do.dsp.mp.microsoft.com",
		},
		TTL:      30 * 24 * time.Hour, // 30 days
		Priority: 90,
	},

	PresetPlayStation: {
		Name:        PresetPlayStation,
		Description: "PlayStation Network game downloads",
		Domains: []string{
			"*.playstation.net",
			"*.sonyentertainmentnetwork.com",
			"gs2.ww.prod.dl.playstation.net",
			"gs2.sonycoment.loris-e.llnwd.net",
			"*.dl.playstation.net",
		},
		TTL:      365 * 24 * time.Hour,
		Priority: 100,
	},

	PresetXbox: {
		Name:        PresetXbox,
		Description: "Xbox Live game downloads",
		Domains: []string{
			"*.xboxlive.com",
			"assets*.xboxlive.com",
			"dlassets*.xboxlive.com",
			"*.assets.xboxlive.com",
			"xvcf*.xboxlive.com",
			"*.xboxlive.cn",
		},
		TTL:      365 * 24 * time.Hour,
		Priority: 100,
	},

	PresetNintendo: {
		Name:        PresetNintendo,
		Description: "Nintendo Switch/eShop downloads",
		Domains: []string{
			"*.nintendo.net",
			"*.cdn.nintendo.net",
			"ccs.cdn.wup.shop.nintendo.net",
			"ecs-lp1.hac.shop.nintendo.net",
			"receive-lp1.dg.srv.nintendo.net",
		},
		TTL:      365 * 24 * time.Hour,
		Priority: 100,
	},

	PresetUbisoft: {
		Name:        PresetUbisoft,
		Description: "Ubisoft Connect game downloads",
		Domains: []string{
			"*.ubi.com",
			"*.ubisoft.com",
			"uplaypc-s-ubisoft.cdn.ubi.com",
			"static3.cdn.ubi.com",
		},
		TTL:      365 * 24 * time.Hour,
		Priority: 100,
	},

	PresetRiot: {
		Name:        PresetRiot,
		Description: "Riot Games (League of Legends, Valorant) downloads",
		Domains: []string{
			"*.riotgames.com",
			"l3cdn.riotgames.com",
			"lol.dyn.riotcdn.net",
			"riotgamespatcher-a.akamaihd.net",
			"riotgamespatcher-b.akamaihd.net",
		},
		TTL:      365 * 24 * time.Hour,
		Priority: 100,
	},

	PresetApple: {
		Name:        PresetApple,
		Description: "Apple software updates and App Store",
		Domains: []string{
			"swcdn.apple.com",
			"swscan.apple.com",
			"updates-http.cdn-apple.com",
			"updates.cdn-apple.com",
			"iosapps.itunes.apple.com",
			"osxapps.itunes.apple.com",
		},
		TTL:      30 * 24 * time.Hour,
		Priority: 90,
	},

	PresetGoogle: {
		Name:        PresetGoogle,
		Description: "Google Play and Android updates",
		Domains: []string{
			"dl.google.com",
			"*.gvt1.com",
			"*.ggpht.com",
			"redirector.gvt1.com",
			"*.c.android.clients.google.com",
		},
		TTL:      30 * 24 * time.Hour,
		Priority: 90,
	},

	PresetLinux: {
		Name:        PresetLinux,
		Description: "Linux distribution package repositories",
		Domains: []string{
			"archive.ubuntu.com",
			"*.archive.ubuntu.com",
			"security.ubuntu.com",
			"*.debian.org",
			"*.fedoraproject.org",
			"*.centos.org",
			"mirrors.*.kernel.org",
		},
		TTL:      7 * 24 * time.Hour, // 7 days - packages change more often
		Priority: 80,
	},
}

// GetPreset returns a preset by name.
func GetPreset(name PresetName) (Preset, bool) {
	p, ok := presets[name]
	return p, ok
}

// GetPresetByString returns a preset by string name.
func GetPresetByString(name string) (Preset, bool) {
	return GetPreset(PresetName(name))
}

// AllPresets returns all available presets as a map.
func AllPresets() map[PresetName]Preset {
	result := make(map[PresetName]Preset, len(presets))
	for k, v := range presets {
		result[k] = v
	}
	return result
}

// PresetNames returns the names of all available presets.
func PresetNames() []PresetName {
	names := make([]PresetName, 0, len(presets))
	for name := range presets {
		names = append(names, name)
	}
	return names
}

// PresetToRule converts a preset to a Rule.
func PresetToRule(preset Preset) *Rule {
	return &Rule{
		Name:        string(preset.Name),
		Domains:     preset.Domains,
		Matcher:     matcher.New(preset.Domains),
		Enabled:     true,
		TTL:         preset.TTL,
		MaxSize:     0, // Unlimited
		Priority:    preset.Priority,
		Methods:     []string{"GET"},
		IgnoreQuery: true, // CDNs typically use query for cache busting
		Preset:      string(preset.Name),
	}
}

// LoadPresets loads rules from a list of preset names.
func LoadPresets(names []string) []*Rule {
	rules := make([]*Rule, 0, len(names))
	for _, name := range names {
		preset, ok := GetPresetByString(name)
		if !ok {
			continue
		}
		rules = append(rules, PresetToRule(preset))
	}
	return rules
}

// PresetInfo provides information about a preset for API responses.
type PresetInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Domains     []string `json:"domains"`
	TTL         string   `json:"ttl"`
	Priority    int      `json:"priority"`
}

// GetPresetInfo returns preset information.
func GetPresetInfo(name PresetName) *PresetInfo {
	preset, ok := GetPreset(name)
	if !ok {
		return nil
	}

	return &PresetInfo{
		Name:        string(preset.Name),
		Description: preset.Description,
		Domains:     preset.Domains,
		TTL:         preset.TTL.String(),
		Priority:    preset.Priority,
	}
}

// AllPresetInfo returns information about all presets.
func AllPresetInfo() []*PresetInfo {
	result := make([]*PresetInfo, 0, len(presets))
	for name := range presets {
		result = append(result, GetPresetInfo(name))
	}
	return result
}
