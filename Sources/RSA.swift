//
//  RSA.swift
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

public struct RSABaseWrapper<RSAT> {
    // MARK: Lifecycle
    public init(_ value: RSAT) {
        self.base = value
    }

    // MARK: Public
    public var base: RSAT
}

public protocol RSANameSpace {
    associatedtype RSAT
    static var rsa: RSAT.Type { get }

    var rsa: RSAT { set get }
}

public extension RSANameSpace {
    static var rsa: RSABaseWrapper<Self>.Type { RSABaseWrapper.self }

    var rsa: RSABaseWrapper<Self> { set { } get { RSABaseWrapper(self) }}
}

public struct DVTRSA {
    // MARK: Public
    public static var publicKey: PublicKey?
    public static var privateKey: PrivateKey?

    /// 设置全局字符串加密的公钥，如果没有设置，每次加密需要传递公钥
    public static var publicPemKey: String? {
        set {
            if let value = newValue {
                do {
                    self.publicKey = try PublicKey(pemEncoded: value)
                    self.publicPem = value
                } catch let error as NSError {
                    assert(false, error.localizedDescription)
                }
            } else {
                self.publicKey = nil
            }
        }
        get {
            self.publicPem
        }
    }

    /// 设置全局字符串解密的私钥，如果没有设置，每次解密需要传递私钥
    public static var privatePemKey: String? {
        set {
            if let value = newValue {
                do {
                    self.privateKey = try PrivateKey(pemEncoded: value)
                    self.privatePem = value
                } catch let error as NSError {
                    assert(false, error.localizedDescription)
                }
            } else {
                self.privateKey = nil
            }
        }
        get {
            self.privatePem
        }
    }

    // MARK: Private
    private static var publicPem: String?
    private static var privatePem: String?
}
