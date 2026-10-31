# Third-party notices

ZIPFoundation 0.9.20 is linked via Swift Package Manager. Source: https://github.com/weichsel/ZIPFoundation . Exact revision in Package.resolved.

MIT License

Copyright (c) 2017-2025 Thomas Zoechling (https://www.peakstep.com)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


The main application links no signer/transport upstream. A separate AGPL-3.0-only package under Experimental/OfflineSignerLab links pinned CodeSignKit plus Apache-2.0 swift-crypto/swift-asn1 and their included vendored notices. Its LICENSE, README and Package.resolved describe the isolated scope and unresolved security/redistribution audit. It is not linked to or shipped in the main app. Other research references remain documentation only. See docs/PHASE0.md and docs/v2/SIGNING_ENGINE.md.

Experimental source mirror: Experimental/Vendor/CodeSignKit contains upstream Sources from d0c67710fda9a2646b9e829cb2cf443892728371, original copyright headers, full AGPL-3.0 license, and UPSTREAM.md documenting modifications. It is used only by the separate AGPL signing laboratory. The original application's dependency graph remains ZIPFoundation plus system frameworks; no signer/transport dependency is linked there.
