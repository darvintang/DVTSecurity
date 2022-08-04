//
//  Data+RSA.swift
//  DVTSecurity
//
//  Created by darvin on 2022/6/8.
//

/*

 MIT License

 Copyright (c) 2022 darvin http://blog.tcoding.cn

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

extension Data: RSANameSpace { }

public extension RSABaseWrapper where RSAT == Data {
    private var publicKey: PublicKey? {
        return DVTRSA.publicKey
    }

    private var privateKey: PrivateKey? {
        return DVTRSA.privateKey
    }

    private var clearMessage: ClearMessage {
        ClearMessage(data: self.base)
    }

    /// 校验一个签名
    /// - Parameters:
    ///   - publicPemKey: 公钥
    ///   - signature: 签名
    ///   - digestType: 签名类型
    /// - Returns: 结果
    func verify(_ publicPemKey: String? = nil, signature data: Data, digestType type: Signature.DigestType = .sha1) throws -> Bool {
        let clear = self.clearMessage
        let signature = Signature(data: data)
        var publicKey: PublicKey?
        if let pemKey = publicPemKey {
            publicKey = try PublicKey(pemEncoded: pemKey)
        }
        guard let key = publicKey ?? self.publicKey else {
            throw SwiftyRSAError.notAPublicKey
        }
        return try clear.verify(with: key, signature: signature, digestType: type)
    }

    /// 获取一个RSA签名
    /// - Parameters:
    ///   - privateKey: 私钥
    ///   - algorithm: 签名类型
    /// - Returns: 签名
    func signed(_ privatePemKey: String? = nil, digestType type: Signature.DigestType = .sha1) throws -> Data {
        let clear = self.clearMessage
        var privateKey: PrivateKey?
        if let pemKey = privatePemKey {
            privateKey = try PrivateKey(pemEncoded: pemKey)
        }
        guard let key = privateKey ?? self.privateKey else {
            throw SwiftyRSAError.notAPrivateKey
        }

        return try clear.signed(with: key, digestType: type).data
    }

    /// 获取加密后的数据
    /// - Parameter privateKey: 公钥
    /// - Returns: 加密后的结果
    func encrypt(_ publicPemKey: String? = nil, padding type: NewPadding = .rsaEncryptionPKCS1) throws -> Data {
        let clear = self.clearMessage
        var publicKey: PublicKey?
        if let pemKey = publicPemKey {
            publicKey = try PublicKey(pemEncoded: pemKey)
        }
        guard let key = publicKey ?? self.publicKey else {
            throw SwiftyRSAError.notAPublicKey
        }
        return try clear.encrypted(with: key, padding: type).data
    }

    /// 获取解密后的数据
    /// - Parameter privateKey: 私钥
    /// - Returns: 解密后的结果
    func decrypt(_ privatePemKey: String? = nil, padding type: NewPadding = .rsaEncryptionPKCS1) throws -> Data {
        let encrypted = EncryptedMessage(data: self.base)

        var privateKey: PrivateKey?
        if let pemKey = privatePemKey {
            privateKey = try PrivateKey(pemEncoded: pemKey)
        }
        guard let key = privateKey ?? self.privateKey else {
            throw SwiftyRSAError.notAPrivateKey
        }
        return try encrypted.decrypted(with: key, padding: type).data
    }
}
