import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import starlightThemeGalaxy from "starlight-theme-galaxy";
import starlightClientMermaid from "@pasqal-io/starlight-client-mermaid";

export default defineConfig({
  // site and base are set via CLI args in CI (from actions/configure-pages)
  integrations: [
    starlight({
      title: "Bifrost Proxy",
      description: "A Go-based proxy system with client-server architecture, supporting WireGuard/OpenVPN tunnels, domain-based routing, and multiple authentication modes",
      logo: { src: "/logo.svg", alt: "Bifrost Proxy" },
      favicon: "/logo.svg",
      plugins: [starlightThemeGalaxy(), starlightClientMermaid()],
      customCss: ["./src/styles/custom.css"],
      social: [
        { icon: "github", label: "GitHub", href: "https://github.com/rennerdo30/bifrost-proxy" },
      ],
      sidebar: [
        { label: "Home", slug: "index" },
        { label: "Getting Started", slug: "getting-started" },
        {
          label: "Configuration",
          items: [
            { label: "Overview", slug: "configuration" },
            { label: "Backends", slug: "backends" },
            { label: "VPN Providers", slug: "vpn-providers" },
            { label: "Authentication", slug: "authentication" },
            { label: "VPN Mode", slug: "vpn-mode" },
            { label: "Mesh Networking", slug: "mesh-networking" },
            { label: "HTTP Cache", slug: "cache" },
          ],
        },
        {
          label: "Clients",
          items: [
            { label: "Desktop Client", slug: "desktop-client" },
            { label: "Mobile Client", slug: "mobile-client" },
          ],
        },
        {
          label: "Features",
          items: [
            { label: "Traffic Debugging", slug: "features/traffic-debugging" },
          ],
        },
        { label: "Deployment", slug: "deployment" },
        {
          label: "Operations",
          items: [
            { label: "CLI Reference", slug: "cli-reference" },
            { label: "Monitoring", slug: "monitoring" },
            { label: "Security", slug: "security" },
            { label: "Troubleshooting", slug: "troubleshooting" },
          ],
        },
        { label: "API Reference", slug: "api" },
        {
          label: "Internals",
          items: [
            { label: "Frame Processing", slug: "internals/frame-processing" },
          ],
        },
        {
          label: "Development",
          items: [
            { label: "Contributing", slug: "contributing" },
            { label: "Changelog", slug: "changelog" },
          ],
        },
      ],
    }),
  ],
});
