// Package main is the entry point for the Bifrost Quick Access desktop application.
// This Wails-based app provides a lightweight popup interface for normal users
// while the full web dashboard remains available for power users.
package main

import (
	"embed"
	"log/slog"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed build/appicon.png
var appIcon []byte

func main() {
	// Configure structured logging
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Create application with options
	app := NewApp()

	err := wails.Run(&options.App{
		Title:     "Bifrost Quick Access",
		Width:     340,
		Height:    580,
		MinWidth:  300,
		MinHeight: 500,
		MaxWidth:  450,
		MaxHeight: 700,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 10, G: 14, B: 23, A: 255}, // #0a0e17
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		Bind: []interface{}{
			app,
		},
		// Frameless window for modern look
		Frameless: false,
		// Start hidden for tray-first experience
		StartHidden: false,
		// Windows-specific options
		Windows: &windows.Options{
			WebviewIsTransparent:              false,
			WindowIsTranslucent:               false,
			DisableWindowIcon:                 false,
			DisableFramelessWindowDecorations: false,
			WebviewUserDataPath:               "",
			WebviewBrowserPath:                "",
			Theme:                             windows.Dark,
		},
		// macOS-specific options
		Mac: &mac.Options{
			TitleBar: &mac.TitleBar{
				TitlebarAppearsTransparent: true,
				HideTitle:                  false,
				HideTitleBar:               false,
				FullSizeContent:            true,
				UseToolbar:                 false,
			},
			Appearance:           mac.NSAppearanceNameDarkAqua,
			WebviewIsTransparent: true,
			WindowIsTranslucent:  true,
		},
		// Linux-specific options
		Linux: &linux.Options{
			Icon:                appIcon,
			WindowIsTranslucent: false,
		},
	})

	if err != nil {
		slog.Error("failed to start application", "error", err)
		os.Exit(1)
	}
}
