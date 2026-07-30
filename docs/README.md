# netscope Documentation

Everything you need to use, understand, and extend netscope.

## For Users

| Document | What it covers |
|----------|---------------|
| [Setup Guide](setup.md) | Prerequisites, build instructions, troubleshooting |
| [TUI Guide](tui.md) | CLI flags, views, colors, keyboard shortcuts, headless mode |
| [Filter Cookbook](filters.md) | Ready-to-paste BPF filters for common tasks |
| [FAQ & Troubleshooting](faq.md) | Common problems and their fixes |
| [Kullanım Kılavuzu (Türkçe)](KULLANIM.md) | Türkçe tam kullanım kılavuzu |
| [Sıfırdan Başlayanlar İçin Rehber (Türkçe)](SIFIR_BASLANGIC_KULLANIM_REHBERI.md) | Hiç bilmeyenler için sıfırdan adım adım ağ analizi kılavuzu |
| [SOC Kurumsal Kontrol Listesi (Türkçe)](SOC_ENTERPRISE_KURUMSAL_CHECKLIST.md) | 143 maddelik kurumsal SOC 7×24 operasyonları onay kutucuklu denetim listesi |
| [Desktop Guide](desktop.md) | Tauri desktop app: build, commands, frontend |
| [SIEM Differentiation Spec](SIEM_DIFFERENTIATION.md) | 7-phase Explanatory SIEM differentiation specification |
| [SIEM Integration Guide](SIEM_INTEGRATION_GUIDE.md) | Technical & API guide for SIEM connectors, OCSF, STIX, Analyst Command Center |

## For Contributors

| Document | What it covers |
|----------|---------------|
| [Architecture](architecture.md) | Crate layout, data flow, dispatch chain, CI/CD |
| [Core API](core.md) | Packet, Protocol, CaptureEngine, StatsEngine, NameCache |
| [Dissector Guide](dissectors.md) | Summary conventions, dispatch logic, how to add a protocol |
| [CI/CD Guide](ci-cd.md) | Pipeline details, release process, adding platforms |

## Quick Links

- **First time?** Start with the [Sıfırdan Başlayanlar İçin Rehber](SIFIR_BASLANGIC_KULLANIM_REHBERI.md) or [Setup Guide](setup.md).
- **Something broken?** Check the [FAQ](faq.md).
- **Want to add a protocol dissector?** Read the [Dissector Guide](dissectors.md) — it's a ~50 line change.
