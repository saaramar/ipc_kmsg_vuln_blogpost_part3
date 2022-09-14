xcrun --sdk iphoneos clang -arch arm64 -framework IOKit -framework IOSurface -framework CoreFoundation iosurface.c poc.c -O3 -o poc
codesign -s - poc --entitlement entitlements.xml -f
