#!/usr/bin/env python3
"""Check Parser Studio brand favicon metadata and assets with stdlib only."""
import re
import struct
import unittest
from pathlib import Path
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "public"
HTML = ROOT / "index.html"


class AppFaviconTests(unittest.TestCase):
    def test_app_links_local_icons(self):
        content = HTML.read_text(encoding="utf-8")
        self.assertIn("<title>Parser Studio — XDR Labs</title>", content)
        self.assertRegex(content, r'<link rel="icon" type="image/svg\+xml" href="/favicon\.svg"')
        self.assertRegex(content, r'<link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32\.png"')
        self.assertRegex(content, r'<link rel="shortcut icon" type="image/x-icon" href="/favicon\.ico"')
        self.assertRegex(content, r'<link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon\.png"')
        for file in re.findall(r'<link (?:rel="icon"|rel="shortcut icon"|rel="apple-touch-icon")\b[^>]*href="(/[^"]+)"', content):
            self.assertTrue((PUBLIC / file.lstrip("/")).is_file(), file)
            self.assertTrue((PUBLIC / file.lstrip("/")).stat().st_size > 64, file)
        self.assertNotIn("http://", content)

    def test_vector_brand_icon(self):
        text = (PUBLIC / "favicon.svg").read_text(encoding="utf-8")
        root = ElementTree.fromstring(text)
        self.assertEqual(root.attrib["viewBox"], "0 0 64 64")
        self.assertIn("#1F59E0", text)
        self.assertIn("Parser Studio", text)
        self.assertNotIn("<script", text.lower())
        self.assertNotIn('href="http', text)
        self.assertNotIn("<image", text.lower())

    def test_png_sizes(self):
        for filename, side in (
            ("favicon-16x16.png", 16),
            ("favicon-32x32.png", 32),
            ("favicon-48x48.png", 48),
            ("apple-touch-icon.png", 180),
            ("icon-192.png", 192),
        ):
            with self.subTest(filename=filename):
                data = (PUBLIC / filename).read_bytes()
                self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
                self.assertEqual(struct.unpack(">II", data[16:24]), (side, side))
                self.assertLess(len(data), 50_000)

    def test_ico_contains_standard_sizes(self):
        data = (PUBLIC / "favicon.ico").read_bytes()
        reserved, icon_type, count = struct.unpack_from("<HHH", data)
        self.assertEqual((reserved, icon_type, count), (0, 1, 3))
        sizes = set()
        for i in range(count):
            width, height, _palette, _reserved, _planes, _bpp, byte_count, offset = struct.unpack_from(
                "<BBBBHHII", data, 6 + 16 * i
            )
            sizes.add((width or 256, height or 256))
            self.assertGreater(byte_count, 64)
            self.assertLessEqual(offset + byte_count, len(data))
        self.assertEqual(sizes, {(16, 16), (32, 32), (48, 48)})


if __name__ == "__main__":
    unittest.main()
