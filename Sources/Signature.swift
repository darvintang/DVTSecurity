//
//  Signature.swift
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

import Foundation

public class Signature {
    // MARK: Lifecycle
    /// Creates a signature with data.
    ///
    /// - Parameter data: Data of the signature
    public init(data: Data) {
        self.data = data
    }

    /// Creates a signature with a base64-encoded string.
    ///
    /// - Parameter base64String: Base64-encoded representation of the signature data.
    /// - Throws: SecurityError.RSA
    public convenience init(base64Encoded base64String: String) throws {
        guard let data = Data(base64Encoded: base64String) else {
            throw SecurityError.RSA.invalidBase64String
        }
        self.init(data: data)
    }

    // MARK: Public
    public enum DigestType {
        case sha1
        case sha224
        case sha256
        case sha384
        case sha512

        // MARK: Internal
        var algorithm: AlgorithmType {
            switch self {
                case .sha1: return .rsaSignatureDigestPKCS1v15SHA1
                case .sha224: return .rsaSignatureDigestPKCS1v15SHA224
                case .sha256: return .rsaSignatureDigestPKCS1v15SHA256
                case .sha384: return .rsaSignatureDigestPKCS1v15SHA384
                case .sha512: return .rsaSignatureDigestPKCS1v15SHA512
            }
        }
    }

    /// Data of the signature
    public let data: Data

    /// Returns the base64 representation of the signature.
    public var base64String: String {
        return self.data.base64EncodedString()
    }
}
