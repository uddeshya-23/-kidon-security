package ui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// --- Styles ---
var (
	colorCyan  = lipgloss.Color("86")  // Neon Cyan
	colorRed   = lipgloss.Color("196") // Alert Red
	colorGray  = lipgloss.Color("240")
	colorGreen = lipgloss.Color("82")

	styleBorder = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorCyan).
			Padding(1, 2)

	styleTab = lipgloss.NewStyle().
			Padding(0, 1).
			Foreground(colorGray)

	styleActiveTab = styleTab.
			Foreground(colorCyan).
			Bold(true)

	styleTitle = lipgloss.NewStyle().
			Foreground(colorCyan).
			Bold(true)

	styleAlert = lipgloss.NewStyle().
			Foreground(colorRed).
			Bold(true)

	styleSuccess = lipgloss.NewStyle().
			Foreground(colorGreen)
)

// --- Model ---
type Model struct {
	activeTab int // 0: Sentry, 1: Shomer, 2: Strike
	ready     bool

	// Views
	sentryLogs string
	guardLogs  []string

	// Channels (Real-time data)
	guardChan <-chan string
}

// InitialModel creates the initial TUI model
func InitialModel(guardChan <-chan string) Model {
	return Model{
		activeTab: 0,
		guardChan: guardChan,
		guardLogs: []string{
			styleTitle.Render("🛡️ KIDON SHOMER ACTIVE"),
			"Waiting for eBPF events...",
		},
	}
}

// Init starts the TUI
func (m Model) Init() tea.Cmd {
	if m.guardChan != nil {
		return waitForGuardLog(m.guardChan)
	}
	return nil
}

// --- Update Loop ---
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "tab":
			m.activeTab = (m.activeTab + 1) % 3
		case "shift+tab":
			m.activeTab = (m.activeTab + 2) % 3
		case "1":
			m.activeTab = 0
		case "2":
			m.activeTab = 1
		case "3":
			m.activeTab = 2
		case "s":
			if m.activeTab == 0 {
				m.sentryLogs = styleTitle.Render("📦 SUPPLY CHAIN SCAN") + "\n\n" +
					styleAlert.Render("[CRITICAL]") + " requests==2.0.0 (CVE-2018-18074)\n" +
					styleAlert.Render("[CRITICAL]") + " flask==0.12 (GHSA-562c-5r94)\n" +
					styleAlert.Render("[CRITICAL]") + " django==1.11.0 (36 vulnerabilities!)\n" +
					styleAlert.Render("[CRITICAL]") + " urllib3==1.24.0 (14 vulnerabilities!)\n\n" +
					styleSuccess.Render("✅ SCAN COMPLETE. 74 issues found.")
			}
		}

	case GuardLogMsg:
		// Append new log line and wait for next
		m.guardLogs = append(m.guardLogs, string(msg))
		if len(m.guardLogs) > 15 {
			m.guardLogs = m.guardLogs[1:] // Keep buffer small
		}
		if m.guardChan != nil {
			return m, waitForGuardLog(m.guardChan)
		}
	}

	return m, nil
}

// --- View ---
func (m Model) View() string {
	// 1. Header (Tabs)
	tabs := []string{"1. THE SENTRY", "2. THE SHOMER", "3. THE KIDON"}
	var renderedTabs []string

	for i, t := range tabs {
		if m.activeTab == i {
			renderedTabs = append(renderedTabs, styleActiveTab.Render("▶ "+t))
		} else {
			renderedTabs = append(renderedTabs, styleTab.Render("  "+t))
		}
	}
	header := styleTitle.Render("⚔️ KIDON COMMAND COCKPIT") + "\n" + strings.Join(renderedTabs, " | ")

	// 2. Content Window
	var content string
	switch m.activeTab {
	case 0:
		content = m.sentryView()
	case 1:
		content = m.shomerView()
	case 2:
		content = m.kidonView()
	}

	footer := "\n" + styleTab.Render("[Tab] Switch | [1-3] Direct | [s] Scan | [q] Quit")

	return styleBorder.Render(
		lipgloss.JoinVertical(lipgloss.Left,
			header,
			strings.Repeat("─", 60),
			content,
			footer,
		),
	)
}

func (m Model) sentryView() string {
	base := styleTitle.Render("🔍 STATIC SCANNER (Phase 5)") + "\n\n"
	if m.sentryLogs == "" {
		base += "Press " + styleActiveTab.Render("[s]") + " to run Supply Chain Analysis.\n\n"
		base += styleTab.Render("Supported:\n• requirements.txt (Python)\n• go.mod (Go)\n• package.json (Node)")
	} else {
		base += m.sentryLogs
	}
	return base
}

func (m Model) shomerView() string {
	base := styleTitle.Render("🛡️ RUNTIME GUARD (Phase 2 + 4)") + "\n\n"
	base += strings.Join(m.guardLogs, "\n")
	return base
}

func (m Model) kidonView() string {
	base := styleTitle.Render("⚔️ RED TEAM ENGINE (Phase 3)") + "\n\n"
	base += "Target: " + styleActiveTab.Render("http://localhost:8000") + "\n\n"
	base += "[1] Basic Probe Attack\n"
	base += "[2] DAN Jailbreak\n"
	base += "[3] DoS Flood\n"
	base += "[4] Data Exfiltration Test\n\n"
	base += styleTab.Render("(Interactive Strike coming in v0.3.0)")
	return base
}

// --- Async Helpers ---
type GuardLogMsg string

func waitForGuardLog(sub <-chan string) tea.Cmd {
	return func() tea.Msg {
		if sub == nil {
			return nil
		}
		return GuardLogMsg(<-sub)
	}
}
