//
//  ClearMessage.swift
//  SwiftyRSA
//
//  Created by Lois Di Qual on 5/18/17.
//  Copyright © 2017 Scoop. All rights reserved.
//

import Foundation
import Security

public class ClearMessage: Message {
    /// Data of the message
    public let data: Data

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
    /// - Throws: SwiftyRSAError
    public convenience init(string: String, using encoding: String.Encoding) throws {
        guard let data = string.data(using: encoding) else {
            throw SwiftyRSAError.stringToDataConversionFailed
        }
        self.init(data: data)
    }

    /// Returns the string representation of the clear message using the specified
    /// string encoding.
    ///
    /// - Parameter encoding: Encoding to use during the string conversion
    /// - Returns: String representation of the clear message
    /// - Throws: SwiftyRSAError
    public func string(encoding: String.Encoding) throws -> String {
        guard let str = String(data: data, encoding: encoding) else {
            throw SwiftyRSAError.dataToStringConversionFailed
        }
        return str
    }

    /// Encrypts a clear message with a public key and returns an encrypted message.
    ///
    /// - Parameters:
    ///   - key: Public key to encrypt the clear message with
    ///   - padding: Padding to use during the encryption
    /// - Returns: Encrypted message
    /// - Throws: SwiftyRSAError
    public func encrypted(with key: PublicKey, padding: NewPadding) throws -> EncryptedMessage {
        var error: Unmanaged<CFError>?
        let encryptedData = SecKeyCreateEncryptedData(key.reference, padding, self.data as CFData, &error)

        if let error = error?.takeRetainedValue() {
            throw SwiftyRSAError.encryptFailed(description: error.localizedDescription)
        }
        guard let resultData = encryptedData as? Data else {
            throw SwiftyRSAError.encryptFailed(description: "Encryption result data is empty")
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
    /// - Throws: SwiftyRSAError
    public func signed(with key: PrivateKey, digestType: Signature.DigestType) throws -> Signature {
        var error: Unmanaged<CFError>?
        let signatureData = SecKeyCreateSignature(key.reference, digestType.padding, self.data as CFData, &error)

        if let error = error?.takeRetainedValue() {
            throw SwiftyRSAError.signatureCreateFailed(description: error.localizedDescription)
        }
        guard let resultData = signatureData as? Data else {
            throw SwiftyRSAError.signatureCreateFailed(description: "Signature result data is empty")
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
    /// - Throws: SwiftyRSAError
    public func verify(with key: PublicKey, signature: Signature, digestType: Signature.DigestType) throws -> Bool {
        var error: Unmanaged<CFError>?
        let verify = SecKeyVerifySignature(key.reference, digestType.padding, self.data as CFData, signature.data as CFData, &error)
        if let error = error?.takeRetainedValue() {
            throw SwiftyRSAError.signatureVerifyFailed(description: error.localizedDescription)
        }
        return verify
    }
}
