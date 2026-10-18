#!/bin/sh
# Build "Disk Cleaner.app". Usage: ./build.sh            -> build/Disk Cleaner.app
#                                  ./build.sh install    -> also copy to /Applications and launch
set -e
cd "$(dirname "$0")"
cargo build --release
APP="build/Disk Cleaner.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp target/release/disk-cleaner "$APP/Contents/MacOS/disk-cleaner"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Disk Cleaner</string>
  <key>CFBundleDisplayName</key><string>Disk Cleaner</string>
  <key>CFBundleIdentifier</key><string>com.local.diskcleaner</string>
  <key>CFBundleExecutable</key><string>disk-cleaner</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>LSUIElement</key><true/>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST
# Ad-hoc sign with a designated requirement on the bundle id (not the build's hash), so a
# Full Disk Access grant keeps working after rebuilding.
codesign --force --sign - --identifier com.local.diskcleaner \
  -r='designated => identifier "com.local.diskcleaner"' "$APP"
echo "Built $APP"
if [ "$1" = "install" ]; then
  pkill -x disk-cleaner 2>/dev/null || true
  rm -rf "/Applications/Disk Cleaner.app"
  cp -R "$APP" /Applications/
  open "/Applications/Disk Cleaner.app"
  echo "Installed to /Applications and launched."
fi
