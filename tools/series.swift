// Capture a series of frames from the dashboard, for the demo GIF.
//
// Build:  swiftc -O series.swift -o series
// Usage:  ./series <url> <outdir> <count> <intervalSeconds> <delayBefore> [javascript]
import AppKit
import WebKit
import Foundation

let args = CommandLine.arguments
guard args.count >= 6 else {
    FileHandle.standardError.write("usage: series <url> <outdir> <count> <interval> <delay> [js]\n".data(using: .utf8)!)
    exit(2)
}
let urlString = args[1]
let outDir = args[2]
let count = Int(args[3]) ?? 12
let interval = Double(args[4]) ?? 0.9
let initialDelay = Double(args[5]) ?? 6.0
let script = args.count > 6 ? args[6] : ""

let width = 1280
let height = 1180

try? FileManager.default.createDirectory(atPath: outDir, withIntermediateDirectories: true)

let app = NSApplication.shared
app.setActivationPolicy(.accessory)

final class Series: NSObject, WKNavigationDelegate {
    let webView: WKWebView
    let outDir: String
    let count: Int
    let interval: Double
    let script: String
    var shot = 0

    init(outDir: String, count: Int, interval: Double, script: String) {
        let config = WKWebViewConfiguration()
        config.preferences.setValue(true, forKey: "allowFileAccessFromFileURLs")
        self.webView = WKWebView(frame: NSRect(x: 0, y: 0, width: width, height: height),
                                  configuration: config)
        self.outDir = outDir
        self.count = count
        self.interval = interval
        self.script = script
        super.init()
        webView.navigationDelegate = self
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        DispatchQueue.main.asyncAfter(deadline: .now() + initialDelay) {
            if self.script.isEmpty {
                self.begin()
            } else {
                self.webView.evaluateJavaScript(self.script) { _, error in
                    if let error = error {
                        FileHandle.standardError.write("js error: \(error)\n".data(using: .utf8)!)
                    }
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) { self.begin() }
                }
            }
        }
    }

    func begin() { captureNext() }

    func captureNext() {
        if shot >= count { print("done \(shot) frames"); exit(0) }
        let cfg = WKSnapshotConfiguration()
        cfg.rect = webView.bounds
        webView.takeSnapshot(with: cfg) { image, error in
            guard let image = image, let tiff = image.tiffRepresentation,
                  let rep = NSBitmapImageRep(data: tiff),
                  let png = rep.representation(using: .png, properties: [:]) else {
                FileHandle.standardError.write("snapshot failed\n".data(using: .utf8)!)
                exit(1)
            }
            let path = String(format: "%@/frame-%03d.png", self.outDir, self.shot)
            try? png.write(to: URL(fileURLWithPath: path))
            self.shot += 1
            DispatchQueue.main.asyncAfter(deadline: .now() + self.interval) { self.captureNext() }
        }
    }
}

let series = Series(outDir: outDir, count: count, interval: interval, script: script)
let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: width, height: height),
                      styleMask: [.borderless], backing: .buffered, defer: false)
window.contentView = series.webView
window.orderFrontRegardless()
if let url = URL(string: urlString) {
    series.webView.load(URLRequest(url: url))
} else {
    FileHandle.standardError.write("bad url\n".data(using: .utf8)!)
    exit(2)
}
DispatchQueue.main.asyncAfter(deadline: .now() + initialDelay + Double(count) * interval + 30) {
    FileHandle.standardError.write("timed out\n".data(using: .utf8)!)
    exit(1)
}
app.run()
