Wireshark Traffic Analyzer (Student Demo)
=========================================

Quick student project by Atul Sharma (BCA 1st Year) — single-file demo for GitHub Pages.

What it is
----------
- Single `index.html` (client-side) showing a SOC-style dashboard.
- Originally uses simulated alerts for portfolio presentation.
- Now supports loading a `tshark` JSON export to show *real* parsed results in the browser.

How to create a `tshark` JSON export (locally)
---------------------------------------------
You need `tshark` (comes with Wireshark). On Windows, use Wireshark/TShark package or install via Wireshark installer.

1. Save capture file (example): suspicious-traffic.pcap
2. Export with tshark to JSON:

   tshark -r suspicious-traffic.pcap -T json > capture.json

3. Open `index.html` in a browser (double-click or serve with a simple static server).
4. In the page, use the "Upload" input to load your `capture.json` file, then click **ANALYZE TRAFFIC**.

Notes
-----
- This parser is simple and made for demo purposes (BCA 1st Year vibes 😄). It looks for common fields in tshark JSON: IPs, TCP/UDP ports and TCP SYN flags.
- If your `tshark` JSON has different field names, the parser might not find everything — it's fine for basic captures.

Want improvements?
------------------
- I can add more robust parsing, support direct PCAP parsing using WASM, or add a small server-side parser.
- I can also add a demo GIF and a README badge.

Contact
-------
Atul Sharma — github.com/AtulSharmx
"Wireshark Traffic Analyzer by Atul Sharma (BCA 1st Year)"

Please give internship 🙏
