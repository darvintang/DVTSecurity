//
//  PublicKey.swift
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

public class PublicKey: Key {
    // MARK: Lifecycle
    /// Creates a public key with a keychain key reference.
    /// This initializer will throw if the provided key reference is not a public RSA key.
    ///
    /// - Parameter reference: Reference to the key within the keychain.
    /// - Throws: SecurityError.RSA
    public required init(reference: SecKey) throws {
        guard RSA.isValidKeyReference(reference, forClass: kSecAttrKeyClassPublic) else {
            throw SecurityError.RSA.notAPublicKey
        }

        self.reference = reference
        self.tag = nil
        self.originalData = nil
    }

    /// Data of the public key as returned by the keychain.
    /// This method throws if SwiftyRSA cannot extract data from the key.
    ///
    /// - Returns: Data of the public key as returned by the keychain.
    /// - Throws: SecurityError.RSA
    public required init(data: Data) throws {
        let tag = UUID().uuidString
        self.tag = tag

        self.originalData = data
        let dataWithoutHeader = try RSA.stripKeyHeader(keyData: data)

        reference = try RSA.addKey(dataWithoutHeader, isPublic: true, tag: tag)
    }

    deinit {
        if let tag = tag {
            RSA.removeKey(tag: tag)
        }
    }

    // MARK: Public
    /// Reference to the key within the keychain
    public let reference: SecKey

    /// Data of the public key as provided when creating the key.
    /// Note that if the key was created from a base64string / DER string / PEM file / DER file,
    /// the data holds the actual bytes of the key, not any textual representation like PEM headers
    /// or base64 characters.
    public let originalData: Data?

    /// Takes an input string, scans for public key sections, and then returns a PublicKey for any valid keys found
    /// - This method scans the file for public key armor - if no keys are found, an empty array is returned
    /// - Each public key block found is "parsed" by `publicKeyFromPEMString()`
    /// - should that method throw, the error is _swallowed_ and not rethrown
    ///
    /// - parameter pemString: The string to use to parse out values
    ///
    /// - returns: An array of `PublicKey` objects
    public static func publicKeys(pemEncoded pemString: String) -> [PublicKey] {
        // If our regexp isn't valid, or the input string is empty, we can't move forward…
        guard let publicKeyRegexp = publicKeyRegex, pemString.count > 0 else {
            return []
        }

        let all = NSRange(location: 0,
                          length: pemString.count)

        let matches = publicKeyRegexp.matches(in: pemString,
                                              options: NSRegularExpression.MatchingOptions(rawValue: 0),
                                              range: all)

        let keys = matches.compactMap { result -> PublicKey? in

            let match = result.range(at: 1)
            let start = pemString.index(pemString.startIndex, offsetBy: match.location)
            let end = pemString.index(start, offsetBy: match.length)

            let thisKey = pemString[start ..< end]

            return try? PublicKey(pemEncoded: String(thisKey))
        }

        return keys
    }

    /// Returns a PEM representation of the public key.
    ///
    /// - Returns: Data of the key, PEM-encoded
    /// - Throws: SecurityError.RSA
    public func pemString() throws -> String {
        let data = try self.data()
        let pem = RSA.format(keyData: data, withPemType: "RSA PUBLIC KEY")
        return pem
    }

    // MARK: Internal
    static let publicKeyRegex: NSRegularExpression? = {
        let publicKeyRegex = "(-----BEGIN PUBLIC KEY-----.+?-----END PUBLIC KEY-----)"
        return try? NSRegularExpression(pattern: publicKeyRegex, options: .dotMatchesLineSeparators)
    }()

    let tag: String? // Only used on iOS 8/9
}
