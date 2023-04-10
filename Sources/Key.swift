//
//  Key.swift
//  DVTSecurity
//
//  Created by Loïs Di Qual on 9/19/16.
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

import Security
import Foundation

public protocol Key: AnyObject {
    // MARK: Lifecycle
    init(data: Data) throws
    init(reference: SecKey) throws
    init(base64Encoded base64String: String) throws
    init(pemEncoded pemString: String) throws
    init(pemNamed pemName: String, in bundle: Bundle) throws
    init(derNamed derName: String, in bundle: Bundle) throws

    // MARK: Internal
    var reference: SecKey { get }
    var originalData: Data? { get }

    func pemString() throws -> String
    func data() throws -> Data
    func base64String() throws -> String
}

public extension Key {
    // MARK: Lifecycle
    /// Creates a public key with a base64-encoded string.
    ///
    /// - Parameter base64String: Base64-encoded public key data
    /// - Throws: SecurityError.RSA
    init(base64Encoded base64String: String) throws {
        guard let data = Data(base64Encoded: base64String, options: [.ignoreUnknownCharacters]) else {
            throw SecurityError.RSA.invalidBase64String
        }
        try self.init(data: data)
    }

    /// Creates a public key with a PEM string.
    ///
    /// - Parameter pemString: PEM-encoded public key string
    /// - Throws: SecurityError.RSA
    init(pemEncoded pemString: String) throws {
        let base64String = try RSA.base64String(pemEncoded: pemString)
        try self.init(base64Encoded: base64String)
    }

    /// Creates a public key with a PEM file.
    ///
    /// - Parameters:
    ///   - pemName: Name of the PEM file
    ///   - bundle: Bundle in which to look for the PEM file. Defaults to the main bundle.
    /// - Throws: SecurityError.RSA
    init(pemNamed pemName: String, in bundle: Bundle = Bundle.main) throws {
        guard let path = bundle.path(forResource: pemName, ofType: "pem") else {
            throw SecurityError.RSA.pemFileNotFound(name: pemName)
        }
        let keyString = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        try self.init(pemEncoded: keyString)
    }

    /// Creates a private key with a DER file.
    ///
    /// - Parameters:
    ///   - derName: Name of the DER file
    ///   - bundle: Bundle in which to look for the DER file. Defaults to the main bundle.
    /// - Throws: SecurityError.RSA
    init(derNamed derName: String, in bundle: Bundle = Bundle.main) throws {
        guard let path = bundle.path(forResource: derName, ofType: "der") else {
            throw SecurityError.RSA.derFileNotFound(name: derName)
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        try self.init(data: data)
    }

    // MARK: Internal
    /// Returns a Base64 representation of the public key.
    ///
    /// - Returns: Data of the key, Base64-encoded
    /// - Throws: SecurityError.RSA
    func base64String() throws -> String {
        return try data().base64EncodedString()
    }

    func data() throws -> Data {
        return try RSA.data(forKeyReference: reference)
    }
}
