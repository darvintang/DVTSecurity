//
//  ClearMessage.swift
//  DVTSecurity
//
//  Created by Lois Di Qual on 5/18/17.
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

public class ClearMessage: Message {
    // MARK: Lifecycle
    /// Creates a clear message with data.
    ///
    /// - Parameter data: Data of the clear message
    public required init(data: Data) {
        self.data = data
    }

    /// Creates a clear message from a string, with the specified encoding.
    ///
    /// - Parameters:
    ///   - string: String value of the clear message
    ///   - encoding: Encoding to use to generate the clear data
    /// - Throws: SecurityError.RSA
    public convenience init(string: String, using encoding: String.Encoding) throws {
        guard let data = string.data(using: encoding) else {
            throw SecurityError.Conversion.stringToDataConversionFailed
        }
        self.init(data: data)
    }

    // MARK: Public
    /// Data of the message
    public let data: Data

    /// Returns the string representation of the clear message using the specified
    /// string encoding.
    ///
    /// - Parameter encoding: Encoding to use during the string conversion
    /// - Returns: String representation of the clear message
    /// - Throws: SecurityError.RSA
    public func string(encoding: String.Encoding) throws -> String {
        guard let str = String(data: data, encoding: encoding) else {
            throw SecurityError.Conversion.dataToStringConversionFailed
        }
        return str
    }

    /// Encrypts a clear message with a public key and returns an encrypted message.
    ///
    /// - Parameters:
    ///   - key: Public key to encrypt the clear message with
    ///   - algorithm: One of SecKeyAlgorithm constants suitable to perform encryption with this key.
    /// - Returns: Encrypted message
    /// - Throws: SecurityError.RSA
    public func encrypted(with key: PublicKey, algorithm type: AlgorithmType) throws -> EncryptedMessage {
        var error: Unmanaged<CFError>?
        let encryptedData = SecKeyCreateEncryptedData(key.reference, type, self.data as CFData, &error)

        if let error = error?.takeRetainedValue() {
            throw SecurityError.RSA.encryptFailed(description: error.localizedDescription)
        }
        guard let resultData = encryptedData as? Data else {
            throw SecurityError.RSA.encryptFailed(description: "Encryption result data is empty")
        }
        return EncryptedMessage(data: resultData)
    }

    /// Signs a clear message using a private key.
    /// The clear message will first be hashed using the specified digest type, then signed
    /// using the provided private key.
    ///
    /// - Parameters:
    ///   - key: Private key to sign the clear message with
    ///   - digestType: Digest
    /// - Returns: Signature of the clear message after signing it with the specified digest type.
    /// - Throws: SecurityError.RSA
    public func signed(with key: PrivateKey, digest type: Signature.DigestType) throws -> Signature {
        var error: Unmanaged<CFError>?
        let signatureData = SecKeyCreateSignature(key.reference, type.algorithm, self.data as CFData, &error)

        if let error = error?.takeRetainedValue() {
            throw SecurityError.RSA.signatureCreateFailed(description: error.localizedDescription)
        }
        guard let resultData = signatureData as? Data else {
            throw SecurityError.RSA.signatureCreateFailed(description: "Signature result data is empty")
        }
        return Signature(data: resultData)
    }

    /// Verifies the signature of a clear message.
    ///
    /// - Parameters:
    ///   - key: Public key to verify the signature with
    ///   - signature: Signature to verify
    ///   - digestType: Digest type used for the signature
    /// - Returns: Result of the verification
    /// - Throws: SecurityError.RSA
    public func verify(with key: PublicKey, signature: Signature, digest type: Signature.DigestType) throws -> Bool {
        var error: Unmanaged<CFError>?
        let verify = SecKeyVerifySignature(key.reference, type.algorithm, self.data as CFData, signature.data as CFData, &error)
        if let error = error?.takeRetainedValue() {
            throw SecurityError.RSA.signatureVerifyFailed(description: error.localizedDescription)
        }
        return verify
    }
}
