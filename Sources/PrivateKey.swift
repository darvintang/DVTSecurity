//
//  PrivateKey.swift
//  DVTSecurity
//
//  Created by Lois Di Qual on 5/17/17.
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

public class PrivateKey: Key {
    // MARK: Lifecycle
    /// Creates a private key with a keychain key reference.
    /// This initializer will throw if the provided key reference is not a private RSA key.
    ///
    /// - Parameter reference: Reference to the key within the keychain.
    /// - Throws: SecurityError.RSA
    public required init(reference: SecKey) throws {
        guard RSA.isValidKeyReference(reference, forClass: kSecAttrKeyClassPrivate) else {
            throw SecurityError.RSA.notAPrivateKey
        }

        self.reference = reference
        self.tag = nil
        self.originalData = nil
    }

    /// Creates a private key with a RSA public key data.
    ///
    /// - Parameter data: Private key data
    /// - Throws: SecurityError.RSA
    public required init(data: Data) throws {
        self.originalData = data
        let tag = UUID().uuidString
        self.tag = tag
        let dataWithoutHeader = try RSA.stripKeyHeader(keyData: data)
        reference = try RSA.addKey(dataWithoutHeader, isPublic: false, tag: tag)
    }

    deinit {
        if let tag = tag {
            RSA.removeKey(tag: tag)
        }
    }

    // MARK: Public
    /// Reference to the key within the keychain
    public let reference: SecKey

    /// Original data of the private key.
    /// Note that it does not contain PEM headers and holds data as bytes, not as a base 64 string.
    public let originalData: Data?

    /// Returns a PEM representation of the private key.
    ///
    /// - Returns: Data of the key, PEM-encoded
    /// - Throws: SecurityError.RSA
    public func pemString() throws -> String {
        let data = try self.data()
        let pem = RSA.format(keyData: data, withPemType: "RSA PRIVATE KEY")
        return pem
    }

    // MARK: Internal
    let tag: String?
}
