//
//  RSAExtension.swift
//  DVTSecurity
//
//  Created by darvin on 2022/6/8.
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

public struct RSABaseWrapper<RSAType> {
    // MARK: Lifecycle
    public init(_ value: RSAType) {
        self.base = value
    }

    // MARK: Public
    public var base: RSAType
}

public protocol RSANameSpace {
    associatedtype RSAType
    static var rsa: RSAType.Type { get }

    var rsa: RSAType { set get }
}

public extension RSANameSpace {
    static var rsa: RSABaseWrapper<Self>.Type { RSABaseWrapper.self }

    var rsa: RSABaseWrapper<Self> { set { } get { RSABaseWrapper(self) }}
}

extension Data: RSANameSpace { }

public extension RSABaseWrapper where RSAType == Data {
    // MARK: Internal
    /// 校验一个签名
    /// - Parameters:
    ///   - publicPemKey: 公钥
    ///   - signature: 签名
    ///   - digestType: 签名类型
    /// - Returns: 结果
    func verify(_ publicPemKey: String? = nil, signature data: Data, digest type: Signature.DigestType = .sha1) throws -> Bool {
        let clear = self.clearMessage
        let signature = Signature(data: data)
        var publicKey: PublicKey?
        if let pemKey = publicPemKey {
            publicKey = try PublicKey(pemEncoded: pemKey)
        }
        guard let key = publicKey ?? self.publicKey else {
            throw SecurityError.RSA.notAPublicKey
        }
        return try clear.verify(with: key, signature: signature, digest: type)
    }

    /// 获取一个RSA签名
    /// - Parameters:
    ///   - privateKey: 私钥
    ///   - algorithm: 签名类型
    /// - Returns: 签名
    func signed(_ privatePemKey: String? = nil, digest type: Signature.DigestType = .sha1) throws -> Data {
        let clear = self.clearMessage
        var privateKey: PrivateKey?
        if let pemKey = privatePemKey {
            privateKey = try PrivateKey(pemEncoded: pemKey)
        }
        guard let key = privateKey ?? self.privateKey else {
            throw SecurityError.RSA.notAPrivateKey
        }

        return try clear.signed(with: key, digest: type).data
    }

    /// 获取加密后的数据
    /// - Parameter privateKey: 公钥
    /// - Returns: 加密后的结果
    func encrypt(_ publicPemKey: String? = nil, algorithm type: AlgorithmType = .rsaEncryptionPKCS1) throws -> Data {
        let clear = self.clearMessage
        var publicKey: PublicKey?
        if let pemKey = publicPemKey {
            publicKey = try PublicKey(pemEncoded: pemKey)
        }
        guard let key = publicKey ?? self.publicKey else {
            throw SecurityError.RSA.notAPublicKey
        }
        return try clear.encrypted(with: key, algorithm: type).data
    }

    /// 获取解密后的数据
    /// - Parameter privateKey: 私钥
    /// - Returns: 解密后的结果
    func decrypt(_ privatePemKey: String? = nil, algorithm type: AlgorithmType = .rsaEncryptionPKCS1) throws -> Data {
        let encrypted = EncryptedMessage(data: self.base)

        var privateKey: PrivateKey?
        if let pemKey = privatePemKey {
            privateKey = try PrivateKey(pemEncoded: pemKey)
        }
        guard let key = privateKey ?? self.privateKey else {
            throw SecurityError.RSA.notAPrivateKey
        }
        return try encrypted.decrypted(with: key, algorithm: type).data
    }

    // MARK: Private
    private var publicKey: PublicKey? {
        return DVTRSAKey.publicKey
    }

    private var privateKey: PrivateKey? {
        return DVTRSAKey.privateKey
    }

    private var clearMessage: ClearMessage {
        ClearMessage(data: self.base)
    }
}

extension String: RSANameSpace { }

public extension RSABaseWrapper where RSAType == String {
    /// 校验RSA签名
    /// - Parameters:
    ///   - publicPemKey: 公钥
    ///   - signature: 签名
    ///   - type: 签名类型
    /// - Returns: 结果
    func verify(_ publicPemKey: String? = nil, signature: String, digest type: Signature.DigestType = .sha1) throws -> Bool {
        guard let signatureData = Data(base64Encoded: signature) else {
            throw SecurityError.Conversion.stringToDataConversionFailed
        }
        guard let signedData = self.base.data(using: .utf8) else {
            throw SecurityError.Conversion.stringToDataConversionFailed
        }
        return try signedData.rsa.verify(publicPemKey, signature: signatureData, digest: type)
    }

    /// 获取一个RSA签名
    /// - Parameters:
    ///   - privatePemKey: 私钥
    ///   - type:类型
    /// - Returns: 签名
    func signed(_ privatePemKey: String? = nil, digest type: Signature.DigestType = .sha1) throws -> String {
        guard let signedData = self.base.data(using: .utf8) else {
            throw SecurityError.Conversion.stringToDataConversionFailed
        }
        let data = try signedData.rsa.signed(privatePemKey, digest: type)
        return data.base64EncodedString()
    }

    /// 获取加密后的字符串
    /// - Parameters:
    ///   - publicPemKey: 公钥
    ///   - algorithm: 类型
    /// - Returns: 加密后的结果
    func encrypt(_ publicPemKey: String? = nil, algorithm type: AlgorithmType = .rsaEncryptionPKCS1) throws -> String {
        guard let baseString = self.base.data(using: .utf8) else {
            throw SecurityError.Conversion.stringToDataConversionFailed
        }
        return try baseString.rsa.encrypt(publicPemKey, algorithm: type).base64EncodedString()
    }

    /// 获取解密后的字符串
    /// - Parameters:
    ///   - privatePemKey: 私钥
    ///   - algorithm: 类型
    /// - Returns: 解密后的结果
    func decrypt(_ privatePemKey: String? = nil, algorithm type: AlgorithmType = .rsaEncryptionPKCS1) throws -> String {
        guard let signedData = Data(base64Encoded: self.base, options: [.ignoreUnknownCharacters]) else {
            throw SecurityError.Conversion.stringToDataConversionFailed
        }
        let data = try signedData.rsa.decrypt(privatePemKey, algorithm: type)
        guard let res = String(data: data, encoding: .utf8) else {
            throw SecurityError.Conversion.dataToStringConversionFailed
        }
        return res
    }
}
