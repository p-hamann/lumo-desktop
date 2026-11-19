# Changelog

## [Unreleased]

### Added

- Proton Mail: Mark messages as read or unread, move them to another folder, and list folders. Moving asks first by default.

## [0.5.9]

### Security

- Security improvements to tool approvals, connectors, credential handling, links and permissions.

### Added

- Connectors: Added an "Always allow" option for tools in settings, which runs the tool without asking even after reading untrusted content and in scheduled tasks.

### Fixed

- macOS: The tray icon now adapts to a dark menu bar.
- macOS: Iframes can navigate again.
- Linux: Dialog messages containing `%` are shown correctly.

## [0.5.8]

### Fixed

- Documents: Native PDF export on macOS.

### Changed

- Connectors: Slack, Google Drive and BigQuery are now experimental and hidden behind a feature flag.
- Search: Refreshed the quick-ask bubble design
- Connectors: SMTP security option now uses `tls` instead of `start_tls`.

### Added

- Connectors: Added research, finance, sales and home connectors.
- MCP: Added a "None (public server)" authentication option for custom MCP servers.

## [0.5.7]

### Fixed

- Windows: Prevented console windows from appearing when running skill scripts.
- macOS: Serialized Keychain access to prevent overlapping credential requests.
- Search: submitted quick ask on press securely.

### Changed

- Connectors: Upgraded Atlassian Rovo v2 MCP endpoint with migration.
- Settings: Clarified that shell commands run without a sandbox.
- macOS: Refreshed dmg layout and background.

### Added

- UI: allow for light and dark themes in desktop settings
- Downloads: in-app notification for file downloads
- Updates: Added loading indicators while checking for updates with Lumo-branded dialogs.
- Menu: Added a Lumo application menu.

## [0.5.6]

### Fixed

- Search: Fixed quick search with prefilled text.

### Changed

- Connectors: Improved OAuth flow initiation and reset behavior.

### Added

- Updates: Added automatic updates and mandatory updates based on a minimum supported version.
- Skills: Added support for skills and plugins, including skills in scheduled tasks and skill scripts that run on the desktop.
- Connectors: Added support for reading images and documents.

## [0.5.5]

### Fixed

- Window: Fixed a vertical split in the Linux window when returning to the foreground.
- Launcher: Added the missing `%u` placeholder to the Linux launcher for deep links.

### Changed

- Connectors: Switched Slack OAuth to a new public Slack app with a custom URI callback.
- macOS: Updated Lumo Desktop to hide from the Dock when its window is closed.
- UI: Polished settings UI elements.

### Added

- MCP: Added more MCP servers to the presets.
- Settings: Added a reset option under General desktop settings, limited to the local account configuration.
- Schedules: Added recurring tasks in Lumo Desktop with OS notification support.
- Telemetry: Added Sentry error reporting.
- Connectors: Added pagination support for tool results.

## [0.5.4]

### Fixed

- Context: Fixed an agentic loop that could get stuck when reaching the maximum context size.
- Reasoning trace: Enabled collapsing tool results on the desktop.

### Changed

- Connectors: Switched to the community Zendesk MCP server using stdio.
- Settings: Made desktop settings accessible from web settings under Desktop app.
- Approval policy: Removed the per-round tool execution budget.

### Added

- Connectors: Added login shell `PATH` resolution for the shell connector.
- MCP: Added Figma to the MCP server presets.

## [0.5.3]

### Fixed

- Composer: Fixed invalid characters appearing in the composer on macOS.
- UI: Added an enablement toggle and improved customization for the Ask Lumo shortcut.
- Window: Fixed drag and drop not working.

### Changed

- Credentials: Migrated Windows secret storage from keyring to DPAPI to work around Credential Manager's 2,560-byte limit.
- MCP: Allowed self-signed certificates for Bridge.

## [0.5.2]

### Changed

- Icon: Updated the Lumo app icon.

### Added

- MCP: Added command resolution from the shell environment for commands such as `npx`.
- MCP: Added Chrome DevTools, Greenhouse, Zendesk, and Grafana to the MCP server presets.
- MCP: Added environment variable support for custom stdio MCP servers.

## [0.5.1]

### Fixed

- Window: Fixed unexpected window repositioning on app startup.
- Artifacts: Enabled the artifact view to open in the app.
- Dictation: Fixed microphone access for dictation on macOS and Linux.
- Links: Fixed external links failing to open in the browser on Linux and Windows.

### Changed

- Connectors: Updated buttons on connector cards in settings to improve usability.

### Added

- Accounts: Added sign-in persistence across app restarts.
- Accounts: Added account switching and separate desktop settings for each account.
- Connectors: Added a Proton Mail Bridge connector for listing, searching, reading, and writing messages.
- Tool execution: Added a continuation prompt when the per-round budget of 10 tool calls was exhausted.
- Menu: Added an About Lumo section to the menu bar and system tray.
- Settings: Added navigation from **Tools → Connectors → Manage Connectors** in the composer to the Connectors tab in settings.
