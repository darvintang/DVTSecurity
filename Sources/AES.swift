//
//  AES.swift
//  DVTSecurity
//
//  Created by darvin on 2023/4/10.
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
import CommonCrypto

private extension Data {
    var bytes: [UInt8] {
        return Array(self)
    }
}

public struct AES {
    // MARK: Lifecycle

    // MARK: - Initialzier
    public init(_ key: String, vector iv: String = "") throws {
        guard key.count == kCCKeySizeAES128 || key.count == kCCKeySizeAES256, let keyData = key.data(using: .utf8) else {
            throw SecurityError.AES.invalidKey
        }

        if !iv.isEmpty {
            guard iv.count == kCCBlockSizeAES128 else {
                throw SecurityError.AES.invalidVector
            }
            self.vector = iv.data(using: .utf8)
        } else {
            self.vector = nil
        }

        self.key = keyData
    }

    // MARK: Public
    public func encrypt(_ data: Data) throws -> Data {
        try crypt(data, option: CCOperation(kCCEncrypt))
    }

    public func decrypt(_ data: Data) throws -> Data {
        try crypt(data, option: CCOperation(kCCDecrypt))
    }

    // MARK: Private
    private let key: Data
    private let vector: Data?

    private func crypt(_ data: Data, option: CCOperation) throws -> Data {
        let cryptLength = data.count + kCCBlockSizeAES128
        var cryptData = Data(count: cryptLength)

        let keyLength = key.count

        var bytesLength = Int(0)
        let status: CCCryptorStatus
        if let vector = self.vector {
            let options = CCOptions(kCCOptionPKCS7Padding)
            status = cryptData.withUnsafeMutableBytes { cryptBytes in
                data.withUnsafeBytes { dataBytes in
                    vector.withUnsafeBytes { ivBytes in
                        self.key.withUnsafeBytes { keyBytes in
                            CCCrypt(option, CCAlgorithm(kCCAlgorithmAES), options, keyBytes.baseAddress, keyLength, ivBytes.baseAddress, dataBytes.baseAddress, data.count, cryptBytes.baseAddress, cryptLength, &bytesLength)
                        }
                    }
                }
            }
        } else {
            let options = CCOptions(kCCOptionPKCS7Padding + kCCOptionECBMode)
            status = cryptData.withUnsafeMutableBytes { cryptBytes in
                data.withUnsafeBytes { dataBytes in
                    self.key.withUnsafeBytes { keyBytes in
                        CCCrypt(option, CCAlgorithm(kCCAlgorithmAES), options, keyBytes.baseAddress, keyLength, nil, dataBytes.baseAddress, data.count, cryptBytes.baseAddress, cryptLength, &bytesLength)
                    }
                }
            }
        }

        guard UInt32(status) == UInt32(kCCSuccess) else {
            if option == kCCDecrypt {
                throw SecurityError.AES.decryptFailed(status: status)
            } else {
                throw SecurityError.AES.encryptFailed(status: status)
            }
        }

        cryptData.removeSubrange(bytesLength ..< cryptData.count)
        return cryptData
    }
}
