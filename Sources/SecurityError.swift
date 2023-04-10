//
//  SecurityError.RSA.swift
//  DVTSecurity
//
//  Created by Lois Di Qual on 5/15/17.
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

public struct SecurityError {
    public enum Conversion: Error {
        case stringToDataConversionFailed
        case dataToStringConversionFailed
    }

    public enum RSA: Error {
        case pemDoesNotContainKey
        case keyRepresentationFailed(error: CFError?)
        case keyGenerationFailed(error: CFError?)
        case keyCreateFailed(error: CFError?)
        case keyAddFailed(status: OSStatus)
        case keyCopyFailed(status: OSStatus)
        case tagEncodingFailed
        case asn1ParsingFailed
        case invalidAsn1RootNode
        case invalidAsn1Structure
        case invalidBase64String
        case chunkDecryptFailed(index: Int)
        case chunkEncryptFailed(index: Int)

        case invalidDigestSize(digestSize: Int, maxChunkSize: Int)

        case pemFileNotFound(name: String)
        case derFileNotFound(name: String)
        case notAPublicKey
        case notAPrivateKey
        case x509CertificateFailed

        case encryptFailed(description: String)
        case decryptFailed(description: String)

        case signatureCreateFailed(description: String)
        case signatureVerifyFailed(description: String)
    }

    public enum AES: Error {
        case invalidKey
        case invalidVector
        case encryptFailed(status: OSStatus)
        case decryptFailed(status: OSStatus)
    }
}

// MARK: Internal
extension SecurityError.RSA: LocalizedError {
    public var errorDescription: String? {
        switch self {
            case .pemDoesNotContainKey:
                return "无法从 PEM 密钥获取数据：剥离标头后无可用数据"
            case let .keyRepresentationFailed(error):
                return "无法从钥匙串中检索关键数据: CFError \(String(describing: error))"
            case let .keyGenerationFailed(error):
                return "无法生成密钥对: CFError: \(String(describing: error))"
            case let .keyCreateFailed(error):
                return "无法从关键数据创建关键引用: CFError \(String(describing: error))"
            case let .keyAddFailed(status):
                return "无法从钥匙串中检索关键数据: OSStatus \(status)"
            case let .keyCopyFailed(status):
                return "无法从钥匙串复制和检索密钥引用: OSStatus \(status)"
            case .tagEncodingFailed:
                return "无法为密钥创建标签数据"
            case .asn1ParsingFailed:
                return "无法解析 ASN1 密钥数据。请在 https://goo.gl/y67 MW6 提交错误"
            case .invalidAsn1RootNode:
                return "无法解析提供的键，因为它的根 ASN1 节点不是序列。密钥可能已损坏"
            case .invalidAsn1Structure:
                return "无法解析提供的密钥，因为它具有意外的 ASN1 结构"
            case .invalidBase64String:
                return "提供的字符串不是有效的 Base 64 字符串"
            case let .chunkDecryptFailed(index):
                return "无法解密索引处的块: \(index)"
            case let .chunkEncryptFailed(index):
                return "无法在索引处加密块: \(index)"

            case let .invalidDigestSize(digestSize, maxChunkSize):
                return "提供的摘要类型产生的大小: \(digestSize) 大于 RSA 密钥的最大块大小:\(maxChunkSize)"
            case let .signatureCreateFailed(description):
                return "无法签署提供的数据: \(description)"
            case let .signatureVerifyFailed(description):
                return "无法验证所提供数据的签名: \(description)"
            case let .pemFileNotFound(name):
                return "找不到名为的 PEM 文件: '\(name)'"
            case let .derFileNotFound(name):
                return "找不到名为的 DER 文件: '\(name)'"
            case .notAPublicKey:
                return "提供的密钥不是有效的 RSA 公钥"
            case .notAPrivateKey:
                return "提供的密钥不是有效的 RSA 私钥"
            case .x509CertificateFailed:
                return "无法在提供的键前添加，因为它具有意外的结构"
            case let .encryptFailed(description):
                return "无法从密钥数据加密: \(description)"
            case let .decryptFailed(description):
                return "无法从密钥数据解密: \(description)"
        }
    }
}

extension SecurityError.AES: LocalizedError {
    public var errorDescription: String? {
        switch self {
            case .invalidKey:
                return "密钥无效"
            case .invalidVector:
                return "偏移量无效"
            case let .encryptFailed(status: status):
                return "加密失败: OSStatus \(status)"
            case let .decryptFailed(status: status):
                return "解密失败: OSStatus \(status)"
        }
    }
}

extension SecurityError.Conversion: LocalizedError {
    public var errorDescription: String? {
        switch self {
            case .stringToDataConversionFailed:
                return "无法使用指定的编码将字符串转换为数据"
            case .dataToStringConversionFailed:
                return "无法将数据转换为字符串表示形式"
        }
    }
}
