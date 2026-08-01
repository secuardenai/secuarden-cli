#!/usr/bin/env swift
import AppKit
import ImageIO
import UniformTypeIdentifiers

guard CommandLine.arguments.count == 3 else {
    fputs("usage: render.swift <frames-directory> <output.gif>\n", stderr)
    exit(2)
}

let framesDirectory = URL(fileURLWithPath: CommandLine.arguments[1])
let outputURL = URL(fileURLWithPath: CommandLine.arguments[2])
let frameURLs = try FileManager.default.contentsOfDirectory(
    at: framesDirectory,
    includingPropertiesForKeys: nil
).filter { $0.pathExtension == "txt" }.sorted { $0.lastPathComponent < $1.lastPathComponent }

guard !frameURLs.isEmpty else {
    fputs("no text frames found\n", stderr)
    exit(1)
}

let width = 960
let height = 640
let padding = 30.0
let font = NSFont.monospacedSystemFont(ofSize: 14, weight: .regular)
let boldFont = NSFont.monospacedSystemFont(ofSize: 14, weight: .semibold)
let background = NSColor(calibratedRed: 0.055, green: 0.067, blue: 0.09, alpha: 1)
let foreground = NSColor(calibratedRed: 0.85, green: 0.89, blue: 0.94, alpha: 1)
let accent = NSColor(calibratedRed: 0.33, green: 0.78, blue: 0.65, alpha: 1)
let warning = NSColor(calibratedRed: 1.0, green: 0.72, blue: 0.31, alpha: 1)
let muted = NSColor(calibratedRed: 0.55, green: 0.62, blue: 0.7, alpha: 1)
let lineHeight = 18.0

guard let destination = CGImageDestinationCreateWithURL(
    outputURL as CFURL,
    UTType.gif.identifier as CFString,
    frameURLs.count,
    nil
) else {
    fputs("could not create GIF destination\n", stderr)
    exit(1)
}

let gifProperties: [CFString: Any] = [
    kCGImagePropertyGIFDictionary: [kCGImagePropertyGIFLoopCount: 0]
]
CGImageDestinationSetProperties(destination, gifProperties as CFDictionary)

for (index, frameURL) in frameURLs.enumerated() {
    let text = try String(contentsOf: frameURL, encoding: .utf8)
    guard let bitmap = NSBitmapImageRep(
        bitmapDataPlanes: nil,
        pixelsWide: width,
        pixelsHigh: height,
        bitsPerSample: 8,
        samplesPerPixel: 4,
        hasAlpha: true,
        isPlanar: false,
        colorSpaceName: .deviceRGB,
        bytesPerRow: 0,
        bitsPerPixel: 0
    ) else {
        fatalError("could not allocate frame")
    }

    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)
    background.setFill()
    NSRect(x: 0, y: 0, width: width, height: height).fill()

    NSColor(calibratedWhite: 0.12, alpha: 1).setFill()
    NSBezierPath(
        roundedRect: NSRect(x: 12, y: 12, width: Double(width) - 24, height: Double(height) - 24),
        xRadius: 10,
        yRadius: 10
    ).fill()

    var y = Double(height) - padding - lineHeight
    for line in text.split(separator: "\n", omittingEmptySubsequences: false) {
        let value = String(line)
        let color: NSColor
        let selectedFont: NSFont
        if value.hasPrefix("$") {
            color = accent
            selectedFont = boldFont
        } else if value.contains("⚠") || value.contains("[SENSITIVE]") || value.contains("Failed") {
            color = warning
            selectedFont = font
        } else if value.hasPrefix("Fixture replay:") || value.hasPrefix("No live agent") || value.hasPrefix("Screen ") {
            color = muted
            selectedFont = font
        } else {
            color = foreground
            selectedFont = font
        }
        (value as NSString).draw(
            at: NSPoint(x: padding, y: y),
            withAttributes: [.font: selectedFont, .foregroundColor: color]
        )
        y -= lineHeight
        if y < padding { break }
    }
    NSGraphicsContext.restoreGraphicsState()

    guard let image = bitmap.cgImage else {
        fatalError("could not create image frame")
    }
    let delay = index == frameURLs.count - 1 ? 4.0 : 2.8
    let frameProperties: [CFString: Any] = [
        kCGImagePropertyGIFDictionary: [kCGImagePropertyGIFDelayTime: delay]
    ]
    CGImageDestinationAddImage(destination, image, frameProperties as CFDictionary)
}

guard CGImageDestinationFinalize(destination) else {
    fputs("could not finalize GIF\n", stderr)
    exit(1)
}
