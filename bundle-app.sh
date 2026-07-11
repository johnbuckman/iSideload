#!/bin/bash
# Build InstallerApp and bundle it into iSideload.app (repo-relative).
#   ./bundle-app.sh [output-dir]     default output: /Applications/iSideload.app
set -e
cd "$(dirname "$0")"
swift build --product InstallerApp
BINDIR=$(swift build --show-bin-path)
APP="${1:-/Applications}/iSideload.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BINDIR/InstallerApp" "$APP/Contents/MacOS/iSideload"
cp -R "$BINDIR/OpenSSL.framework" "$APP/Contents/MacOS/OpenSSL.framework"
cp icon/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>iSideload</string>
  <key>CFBundleDisplayName</key><string>iSideload</string>
  <key>CFBundleIdentifier</key><string>com.decent.isideload</string>
  <key>CFBundleExecutable</key><string>iSideload</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleVersion</key><string>0.1</string>
  <key>CFBundleShortVersionString</key><string>0.1</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>NSPrincipalClass</key><string>NSApplication</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>LSUIElement</key><true/>
</dict></plist>
PLIST

# ad-hoc sign WITHOUT hardened runtime so it can dlopen AOSKit/AuthKit for Anisette
codesign --force --deep --sign - "$APP" >/dev/null 2>&1
echo "built + signed: $APP"
