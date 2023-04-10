//
//  EncryptedMessage.swift
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
    /// - Throws: SecurityError.RSA
    public func decrypted(with key: PrivateKey, algorithm type: AlgorithmType) throws -> ClearMessage {
        var error: Unmanaged<CFError>?
        let decryptedData = SecKeyCreateDecryptedData(key.reference, type, self.data as CFData, &error)

        if let error = error?.takeRetainedValue() {
            throw SecurityError.RSA.decryptFailed(description: error.localizedDescription)
        }

        guard let resultData = decryptedData as? Data else {
            throw SecurityError.RSA.decryptFailed(description: "Decryption result data is empty")
        }

        return ClearMessage(data: resultData)
    }
}
