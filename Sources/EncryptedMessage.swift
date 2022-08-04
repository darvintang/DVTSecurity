//
//  EncryptedMessage.swift
//  SwiftyRSA
//
//  Created by Lois Di Qual on 5/18/17.
//  Copyright © 2017 Scoop. All rights reserved.
//

import Foundation

public class EncryptedMessage: Message {
    /// Data of the message
    public let data: Data

    /// Creates an encrypted message with data.
    ///
    /// - Parameter data: Data of the encrypted message.
    public required init(data: Data) {
        self.data = data
    }

    /// Decrypts an encrypted message with a private key and returns a clear message.
    ///
    /// - Parameters:
    ///   - key: Private key to decrypt the mssage with
    ///   - padding: Padding to use during the decryption
    /// - Returns: Clear message
    /// - Throws: SwiftyRSAError
    public func decrypted(with key: PrivateKey, padding: NewPadding) throws -> ClearMessage {
        var error: Unmanaged<CFError>?
        let decryptedData = SecKeyCreateDecryptedData(key.reference, padding, self.data as CFData, &error)

        if let error = error?.takeRetainedValue() {
            throw SwiftyRSAError.decryptFailed(description: error.localizedDescription)
        }

        guard let resultData = decryptedData as? Data else {
            throw SwiftyRSAError.decryptFailed(description: "Decryption result data is empty")
        }

        return ClearMessage(data: resultData)
    }
}
