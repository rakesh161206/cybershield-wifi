// Render the CyberShield dashboard to PNG using WKWebView.
//
// No browser is installed on this machine, so we drive WebKit directly:
// load the live dashboard from the running server, wait for it to settle,
// then snapshot the view.
//
// Build:  swiftc -O shot.swift -o shot
// Usage:  ./shot <url> <output.png> [width] [height] [delay-seconds] [javascript]
import AppKit
import WebKit
import Foundation

let args = CommandLine.arguments
guard args.count >= 3 else {
    FileHandle.standardError.write("usage: shot <url> <out.png> [w] [h] [delay] [js]\n".data(using: .utf8)!)
    exit(2)
}
let urlString = args[1]
let outPath = args[2]
let width = args.count > 3 ? Int(args[3]) ?? 1440 : 1440
let height = args.count > 4 ? Int(args[4]) ?? 1200 : 1200
let delay = args.count > 5 ? Double(args[5]) ?? 4.0 : 4.0
let script = args.count > 6 ? args[6] : ""

let app = NSApplication.shared
app.setActivationPolicy(.accessory)

final class Shooter: NSObject, WKNavigationDelegate {
    let webView: WKWebView
    let outPath: String
    let delay: Double
    let script: String
    var done = false

    init(outPath: String, delay: Double, script: String) {
        let config = WKWebViewConfiguration()
        config.preferences.setValue(true, forKey: "allowFileAccessFromFileURLs")
        self.webView = WKWebView(frame: NSRect(x: 0, y: 0, width: width, height: height),
                                  configuration: config)
        self.outPath = outPath
        self.delay = delay
        self.script = script
        super.init()
        webView.navigationDelegate = self
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        // Give the dashboard time to fetch its first payloads and render.
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
            if self.script.isEmpty {
                self.snapshot()
            } else {
                self.webView.evaluateJavaScript(self.script) { _, error in
                    if let error = error {
                        FileHandle.standardError.write("js error: \(error)\n".data(using: .utf8)!)
                    }
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) { self.snapshot() }
                }
            }
        }
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        FileHandle.standardError.write("navigation failed: \(error)\n".data(using: .utf8)!)
        exit(1)
    }

    func snapshot() {
        let cfg = WKSnapshotConfiguration()
        cfg.rect = webView.bounds
        webView.takeSnapshot(with: cfg) { image, error in
            guard let image = image else {
                FileHandle.standardError.write("snapshot failed: \(String(describing: error))\n".data(using: .utf8)!)
                exit(1)
            }
            guard let tiff = image.tiffRepresentation,
                  let rep = NSBitmapImageRep(data: tiff),
                  let png = rep.representation(using: .png, properties: [:]) else {
                FileHandle.standardError.write("png encode failed\n".data(using: .utf8)!)
                exit(1)
            }
            do {
                try png.write(to: URL(fileURLWithPath: self.outPath))
                print("wrote \(self.outPath) \(image.size.width)x\(image.size.height)")
                self.finish()
            } catch {
                FileHandle.standardError.write("write failed: \(error)\n".data(using: .utf8)!)
                exit(1)
            }
        }
    }

    func finish() {
        if !done { done = true; exit(0) }
    }
}

let shooter = Shooter(outPath: outPath, delay: delay, script: script)
let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: width, height: height),
                      styleMask: [.borderless],
                      backing: .buffered, defer: false)
window.contentView = shooter.webView
window.orderFrontRegardless()
if let url = URL(string: urlString) {
    shooter.webView.load(URLRequest(url: url))
} else {
    FileHandle.standardError.write("bad url\n".data(using: .utf8)!)
    exit(2)
}

// Keep the run loop alive; the snapshot callback exits the process.
DispatchQueue.main.asyncAfter(deadline: .now() + delay + 30) {
    FileHandle.standardError.write("timed out\n".data(using: .utf8)!)
    exit(1)
}
app.run()
