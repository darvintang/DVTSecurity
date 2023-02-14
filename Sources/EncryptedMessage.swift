//
//  EncryptedMessage.swift
//  SwiftyRSA
//
//  Created by Lois Di Qual on 5/18/17.
//  Copyright © 2017 Scoop. All rights reserved.
//

import Foundation

public class EncryptedMessage: Message {
    // MARK: Lifecycle
    /// Creates an encrypted message with data.
    ///
    /// - Parameter data: Data of the encrypted message.
    public required init(data: Data) {
        self.data = data
    }

    // MARK: Public
    /// Data of the message
    public let data: Data

    /// Decrypts an encrypted message with a private key and returns a clear message.
    ///
    /// - Parameters:
    ///   - key: Private key to decrypt the mssage with
    ///   - algorithm: One of SecKeyAlgorithm constants suitable to perform encryption with this key.
    /// - Returns: Clear message
    /// - Throws: SwiftyRSAError
    public func decrypted(with key: PrivateKey, algorithm type: AlgorithmType) throws -> ClearMessage {
        var error: Unmanaged<CFError>?
        let decryptedData = SecKeyCreateDecryptedData(key.reference, type, self.data as CFData, &error)

        if let error = error?.takeRetainedValue() {
            throw SwiftyRSAError.decryptFailed(description: error.localizedDescription)
        }

        guard let resultData = decryptedData as? Data else {
            throw SwiftyRSAError.decryptFailed(description: "Decryption result data is empty")
        }

        return ClearMessage(data: resultData)
    }
}
