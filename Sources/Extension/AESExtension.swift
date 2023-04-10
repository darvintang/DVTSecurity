//
//  AESExtension.swift
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

public struct AESBaseWrapper<AESType> {
    // MARK: Lifecycle
    public init(_ value: AESType) {
        self.base = value
    }

    // MARK: Public
    public var base: AESType
}

public protocol AESNameSpace {
    associatedtype AESType
    static var rsa: AESType.Type { get }

    var rsa: AESType { set get }
}

public extension AESNameSpace {
    static var aes: AESBaseWrapper<Self>.Type { AESBaseWrapper.self }

    var aes: AESBaseWrapper<Self> { set { } get { AESBaseWrapper(self) }}
}

extension String: AESNameSpace { }

public extension AESBaseWrapper where AESType == String {
    /// 获取加密后的字符串
    /// - Parameters:
    ///   - key: 密钥
    ///   - vector: 偏移矢量
    /// - Returns: 加密后的结果
    func encrypt(_ Key: String, vector iv: String? = nil) throws -> String {
        guard let baseData = self.base.data(using: .utf8) else {
            throw SecurityError.Conversion.stringToDataConversionFailed
        }
        let encryptData = try baseData.aes.encrypt(Key)

        guard let result = String(data: encryptData, encoding: .utf8) else {
            throw SecurityError.Conversion.dataToStringConversionFailed
        }
        return result
    }

    /// 获取解密后的字符串
    /// - Parameters:
    ///   - key: 密钥
    ///   - vector: 类型
    /// - Returns: 解密后的结果
    func decrypt(_ Key: String, vector iv: String? = nil) throws -> String {
        guard let baseData = Data(base64Encoded: self.base, options: [.ignoreUnknownCharacters]) else {
            throw SecurityError.Conversion.stringToDataConversionFailed
        }
        let decryptData = try baseData.aes.decrypt(Key, vector: iv)
        guard let result = String(data: decryptData, encoding: .utf8) else {
            throw SecurityError.Conversion.dataToStringConversionFailed
        }
        return result
    }
}

extension Data: AESNameSpace { }

public extension AESBaseWrapper where AESType == Data {
    /// 获取加密后的数据
    /// - Parameter
    ///   - key: 密钥
    ///   - vector: 偏移矢量
    /// - Returns: 加密后的结果
    func encrypt(_ key: String, vector iv: String? = nil) throws -> Data {
        let aes = try AES(key, vector: iv ?? "")
        return try aes.encrypt(self.base)
    }

    /// 获取解密后的数据
    /// - Parameter
    ///   - key: 密钥
    ///   - vector: 偏移矢量
    /// - Returns: 解密后的结果
    func decrypt(_ key: String, vector iv: String? = nil) throws -> Data {
        let aes = try AES(key, vector: iv ?? "")
        return try aes.decrypt(self.base)
    }
}
