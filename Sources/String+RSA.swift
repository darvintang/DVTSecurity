//
//  String+RSA.swift
//  DVTSecurity
//
//  Created by darvin on 2022/6/8.
//

/*

 MIT License

 Copyright (c) 2021 darvin http://blog.tcoding.cn

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
import SwiftyRSA

extension String: RSANameSpace { }

public extension RSABaseWrapper where RSAT == String {
    /// 校验RSA签名
    /// - Parameters:
    ///   - publicPemKey: 公钥
    ///   - signature: 签名
    ///   - type: 签名类型
    /// - Returns: 结果
    func verify(_ publicPemKey: String? = nil, signature: String, digestType type: Signature.DigestType = .sha1) throws -> Bool {
        guard let signatureData = Data(base64Encoded: signature) else {
            throw SwiftyRSAError.stringToDataConversionFailed
        }
        guard let signedData = self.base.data(using: .utf8) else {
            throw SwiftyRSAError.stringToDataConversionFailed
        }
        return try signedData.rsa.verify(publicPemKey, signature: signatureData, digestType: type)
    }

    /// 获取一个RSA签名
    /// - Parameters:
    ///   - privatePemKey: 私钥
    ///   - type:类型
    /// - Returns: 签名
    func signed(_ privatePemKey: String? = nil, digestType type: Signature.DigestType = .sha1) throws -> String {
        guard let signedData = self.base.data(using: .utf8) else {
            throw SwiftyRSAError.stringToDataConversionFailed
        }
        let data = try signedData.rsa.signed(privatePemKey, digestType: type)
        return data.base64EncodedString()
    }

    /// 获取加密后的字符串
    /// - Parameters:
    ///   - publicPemKey: 公钥
    ///   - type: 类型
    /// - Returns: 加密后的结果
    func encrypt(_ publicPemKey: String? = nil, padding type: Padding = .PKCS1) throws -> String {
        guard let baseString = self.base.data(using: .utf8) else {
            throw SwiftyRSAError.stringToDataConversionFailed
        }
        return try baseString.rsa.encrypt(publicPemKey, padding: type).base64EncodedString()
    }

    /// 获取解密后的字符串
    /// - Parameters:
    ///   - privatePemKey: 私钥
    ///   - type: 类型
    /// - Returns: 解密后的结果
    func decrypt(_ privatePemKey: String? = nil, padding type: Padding = .PKCS1) throws -> String {
        guard let signedData = Data(base64Encoded: self.base, options: [.ignoreUnknownCharacters]) else {
            throw SwiftyRSAError.stringToDataConversionFailed
        }
        let data = try signedData.rsa.decrypt(privatePemKey, padding: type)
        guard let res = String(data: data, encoding: .utf8) else {
            throw SwiftyRSAError.dataToStringConversionFailed
        }
        return res
    }
}
