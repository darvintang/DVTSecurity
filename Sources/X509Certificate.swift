//
//  X509Certificate.swift
//  DVTSecurity
//
//  Created by Stchepinsky Nathan on 24/06/2021.
//

/*

 MIT License

 Copyright (c) 2023 darvin http://blog.tcoding.cn

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.

 */

import Foundation

/// Encoding/Decoding lengths as octets
private extension NSInteger {
    // MARK: Lifecycle
    init?(octetBytes: [CUnsignedChar], startIDx: inout NSInteger) {
        if octetBytes[startIDx] < 128 {
            // Short form
            self.init(octetBytes[startIDx])
            startIDx += 1
        } else {
            // Long form
            let octets = NSInteger(octetBytes[startIDx] as UInt8 - 128)

            if octets > octetBytes.count - startIDx {
                self.init(0)
                return nil
            }

            var result = UInt64(0)

            for octet in 1 ... octets {
                result = (result << 8)
                result = result + UInt64(octetBytes[startIDx + octet])
            }

            startIDx += 1 + octets
            self.init(result)
        }
    }

    // MARK: Internal
    func encodedOctets() -> [CUnsignedChar] {
        // Short form
        if self < 128 {
            return [CUnsignedChar(self)]
        }

        // Long form
        let long = Int(log2(Double(self)) / 8 + 1)
        var len = self
        var result: [CUnsignedChar] = [CUnsignedChar(long + 0x80)]

        for _ in 0 ..< long {
            result.insert(CUnsignedChar(len & 0xFF), at: 1)
            len = len >> 8
        }

        return result
    }
}

public extension Data {
    // This code source come from Heimdall project https://github.com/henrinormak/Heimdall published under MIT Licence

    /// This method prepend the X509 header to a given public key
    func prependx509Header() -> Data {
        let result = NSMutableData()

        let encodingLength: Int = (self.count + 1).encodedOctets().count
        let OID: [CUnsignedChar] = [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
                                    0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00]

        var builder: [CUnsignedChar] = []

        // ASN.1 SEQUENCE
        builder.append(0x30)

        // Overall size, made of OID + bitstring encoding + actual key
        let size = OID.count + 2 + encodingLength + self.count
        let encodedSize = size.encodedOctets()
        builder.append(contentsOf: encodedSize)
        result.append(builder, length: builder.count)
        result.append(OID, length: OID.count)
        builder.removeAll(keepingCapacity: false)

        builder.append(0x03)
        builder.append(contentsOf: (self.count + 1).encodedOctets())
        builder.append(0x00)
        result.append(builder, length: builder.count)

        // Actual key bytes
        result.append(self)

        return result as Data
    }

    func hasX509Header() throws -> Bool {
        let node: Asn1Parser.Node
        do {
            node = try Asn1Parser.parse(data: self)
        } catch {
            throw SecurityError.RSA.asn1ParsingFailed
        }

        // Ensure the raw data is an ASN1 sequence
        guard case let .sequence(nodes) = node else {
            return false
        }

        // Must contain 2 elements, a sequence and a bit string
        if nodes.count != 2 {
            return false
        }

        // Ensure the first node is an ASN1 sequence
        guard case let .sequence(firstNode) = nodes[0] else {
            return false
        }

        // Must contain 2 elements, an object id and NULL
        if firstNode.count != 2 {
            return false
        }

        guard case .objectIdentifier = firstNode[0] else {
            return false
        }

        guard case .null = firstNode[1] else {
            return false
        }

        // The 2sd child has to be a bit string containing a sequence of 2 int
        let last = nodes[1]
        if case let .bitString(secondChildSequence) = last {
            return try secondChildSequence.isAnHeaderlessKey()
        } else {
            return false
        }
    }

    func isAnHeaderlessKey() throws -> Bool {
        let node: Asn1Parser.Node
        do {
            node = try Asn1Parser.parse(data: self)
        } catch {
            throw SecurityError.RSA.asn1ParsingFailed
        }

        // Ensure the raw data is an ASN1 sequence
        guard case let .sequence(nodes) = node else {
            return false
        }

        // Detect whether the sequence only has integers, in which case it's a headerless key
        let onlyHasIntegers = nodes.filter { node -> Bool in
            if case .integer = node {
                return false
            }
            return true
        }.isEmpty

        // Headerless key
        return onlyHasIntegers
    }
}
