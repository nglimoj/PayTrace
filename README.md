# PayTrace – Privacy-Preserving Payment Forensics Engine

PayTrace is a Chrome extension that monitors browser behavior on online payment pages to identify potentially suspicious activity while preserving user privacy. The extension analyzes behavioral signals, network activity, DOM modifications, and browser security indicators without collecting sensitive payment information.

## Features

- **Payment Page Detection**: Automatically identifies checkout/payment pages
- **Network Monitoring**: Tracks fetch, XMLHttpRequest, WebSocket, sendBeacon, and EventSource requests
- **DOM Monitoring**: Detects hidden iframes, dynamic scripts, suspicious overlays, and DOM modifications
- **User Interaction Monitoring**: Tracks behavioral signals (click timings, focus changes, tab switching)
- **Security Checks**: Detects mixed HTTP content, missing HTTPS, suspicious external domains
- **Risk Scoring Engine**: Calculates risk scores based on detected anomalies
- **Modern Dashboard**: Dark UI with pink accents showing real-time monitoring data
- **JSON Export**: Download detailed security reports

## Privacy Commitment

**PayTrace NEVER collects:**
- Credit card numbers
- CVV/CVC codes
- Expiry dates
- Passwords
- Names
- Addresses
- Form contents
- Cookies
- Session tokens

**Only metadata and behavioral signals are stored.**

## Installation

### Method 1: Chrome Developer Mode (Recommended)

1. Download or clone this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable "Developer mode" in the top-right corner
4. Click "Load unpacked"
5. Select the `PayTrace` folder
6. The extension is now installed!

### Method 2: From Source

```bash
git clone <repository-url>
cd PayTrace
# Then follow Method 1 steps
```

## Usage

### Automatic Activation

The extension automatically activates when it detects a payment page. Look for:

- **Badge Color**: 
  - 🟢 Green = Low Risk
  - 🟠 Orange = Medium Risk
  - 🔴 Red = High Risk
  - ⚪ Gray = Inactive

### Manual Check

1. Navigate to any webpage
2. Click the PayTrace extension icon
3. View the dashboard with:
  - Current site information
  - HTTPS status
  - Network activity
  - DOM modifications
  - Risk assessment

### Export Report

1. Open the PayTrace popup
2. Click "Export JSON"
3. The report will be downloaded as `paytrace_report_[domain]_[timestamp].json`

### Reset Data

1. Open the PayTrace popup
2. Click "Reset" to clear all monitoring data for the current session

## Risk Scoring

The extension uses a weighted scoring system:

| Anomaly | Score |
|---------|-------|
| HTTP page | +50 |
| Mixed content | +30 |
| Hidden iframe | +30 |
| Injected script | +25 |
| Suspicious external domain | +20 |
| Many third-party scripts | +15 |
| Multiple redirects | +10-15 |
| Rapid DOM changes | +10 |

**Risk Levels:**
- **Low Risk**: 0-29 points
- **Medium Risk**: 30-59 points
- **High Risk**: 60+ points

## Project Structure

```
PayTrace/
├── manifest.json           # Extension manifest (Manifest V3)
├── background.js           # Service worker for lifecycle management
├── content.js              # Content script for page monitoring
├── popup.html              # Dashboard UI
├── popup.css               # Dashboard styles (dark UI with pink accents)
├── popup.js                # Dashboard logic
├── utils.js                # Utility functions
├── riskEngine.js           # Risk scoring engine
├── reportGenerator.js      # JSON report generation
├── icons/                  # Extension icons
│   ├── icon16.png
│   ├── icon48.png
│   ├── icon128.png
│   └── icon.svg
└── README.md               # This file
```

## Technical Details

### Architecture

- **Manifest V3**: Uses the latest Chrome extension manifest
- **Content Scripts**: Injected into all pages for monitoring
- **Service Worker**: Manages extension lifecycle and badge updates
- **MutationObserver**: Monitors DOM changes in real-time
- **Network Interception**: Hooks into fetch, XHR, WebSocket APIs

### Monitoring Capabilities

#### Network Monitoring
- Request URLs (only domain and path, no query parameters)
- HTTP methods
- Timestamps
- Response status codes
- Request duration
- Request type classification

#### DOM Monitoring
- Hidden iframe detection
- Dynamic script injection tracking
- Suspicious overlay detection
- Invisible input field identification
- DOM modification counting
- Form replacement detection

#### Behavioral Monitoring
- Click timing intervals (no actual clicks recorded)
- Focus change counting
- Tab switching detection
- Page visibility changes

### Security Checks

- HTTPS validation
- Mixed content detection
- Third-party domain analysis
- Suspicious domain identification
- Redirect chain analysis

## Development

### Building Icons

If you want to regenerate the icons:

```powershell
cd icons
powershell -ExecutionPolicy Bypass -File create-simple-icons.ps1
```

Or use the HTML generator:

```bash
cd icons
# Open generate-icons.html in a browser
```

### Testing

1. Load the extension in Developer Mode
2. Navigate to a test payment page (e.g., a demo checkout)
3. Open the popup to view monitoring data
4. Check the badge color updates
5. Export a JSON report to verify data structure

## Browser Compatibility

- Chrome/Edge (Chromium-based): ✅ Fully supported
- Firefox: ❌ Not supported (Manifest V3 differences)
- Safari: ❌ Not supported (different extension API)

## License

This project is provided as-is for educational and security research purposes.

## Disclaimer

This extension is designed for security research and educational purposes. It does not guarantee protection against all types of payment fraud or skimming attacks. Always verify the security of payment pages through multiple means and use reputable payment processors.

## Contributing

Contributions are welcome! Please ensure:
- Code is well-commented
- Privacy principles are maintained
- No sensitive data collection
- Manifest V3 compliance

## Support

For issues or questions:
1. Check this README
2. Review the code comments
3. Test on a demo payment page first

## Version History

- **v1.0.0** (2026-07-02)
  - Initial release
  - Core monitoring features
  - Risk scoring engine
  - JSON export functionality
  - Dark UI with pink accents
