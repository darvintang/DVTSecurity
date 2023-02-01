//
//  KeyChain.swift
//  DVTSecurity
//
//  Created by darvin on 2022/7/12.
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
import Security

private let chainBoolTrue = "KeyChain:True"
private let chainBoolFalse = "KeyChain:False"

public class KeyChain {
    private var uuid: String
    private var synchronizable: Bool
    private var queue: DispatchQueue
    private let KeyChainTestKey = "cn.tcoding.Security.KeyChain.KeyChainTestKey"
    private let serviceName: String

    public init(iCloud synchronizable: Bool = false) {
        self.synchronizable = synchronizable
        self.uuid = UUID().uuidString
        self.queue = DispatchQueue(label: "cn.tcoding.Security.KeyChain.queue.\(UUID().uuidString)")
        self.serviceName = (Bundle.main.infoDictionary?["CFBundleIdentifier"] as? String) ?? ""
    }

    /// 应用分组，跨应用读取数据
    public var group: String?

    /// 测试keychain，在设置group之后如果group设置出错会出现报错异常
    /// - Returns: 测试结果
    public func test() -> Error? {
        self.set(true, for: self.KeyChainTestKey)
    }

    private static let _default = KeyChain()
    public static var `default`: KeyChain {
        _default
    }

    private let userDefaultsPrefix = "UserDefaults_DVTSecurity_Prefix_"
    private static let UDIDStringKey = "cn.tcoding.Security.KeyChain.UDIDStringKey"

    /// udid替代品，通过将udid保存到keychain来定义设备标识，在系统还原之后会被重置
    public static var UDIDString: String {
        var uuidString: String
        if let string = self.default.valueString(for: UDIDStringKey) {
            uuidString = string
        } else if let string = self.default.valueString(for: "cn.tcoding.DVTFoundation.KeyChain.UDIDStringKey") { // 兼容
            uuidString = string
            self.default.set(uuidString, for: UDIDStringKey, use: true)
        } else {
            uuidString = UUID().uuidString
            self.default.set(uuidString, for: UDIDStringKey, use: true)
        }
        return uuidString
    }

    @available(*, unavailable, message: "2.0.1版本之后弃用该方法")
    public var UDIDString: String {
        Self.UDIDString
    }

    private func getError(_ code: OSStatus) -> Error? {
        if errSecSuccess == code {
            return nil
        }
        var domain = ""
        domain = SecCopyErrorMessageString(code, &domain) as? String ?? "系统错误"
        return NSError(domain: domain, code: Int(code))
    }

    @discardableResult
    public func set(_ value: Bool, for key: String, use defaults: Bool = false) -> Error? {
        return self.set(value ? chainBoolTrue : chainBoolFalse, for: key, use: defaults)
    }

    @discardableResult
    public func set(_ value: String, for key: String, use defaults: Bool = false) -> Error? {
        guard let data = value.data(using: .utf8) else {
            return self.getError(errSecDataNotAvailable)
        }
        return self.set(data, for: key, use: defaults)
    }

    @discardableResult
    public func set(_ value: Data, for key: String, use defaults: Bool = false) -> Error? {
        var keyChainItem = self.create(for: key, value: value)
        keyChainItem[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlock
        if defaults {
            UserDefaults.standard.set(value, forKey: self.userDefaultsPrefix + key)
            UserDefaults.standard.synchronize()
        }
        return self.queue.sync {
            let osStatus = SecItemAdd(keyChainItem as CFDictionary, nil)
            switch osStatus {
                case errSecDuplicateItem:
                    return self.getError(SecItemUpdate(keyChainItem as CFDictionary, [kSecValueData: value] as CFDictionary))
                default:
                    return self.getError(osStatus)
            }
        }
    }

    public func valueBool(for key: String) -> Bool? {
        guard let string = self.valueString(for: key) else {
            return nil
        }
        if chainBoolTrue == string {
            return true
        } else if chainBoolFalse == string {
            return false
        }
        return nil
    }

    public func valueString(for key: String) -> String? {
        if let data = self.value(for: key) {
            return String(data: data, encoding: .utf8)
        }
        return nil
    }

    public func value(for key: String) -> Data? {
        var keyChainItem = self.create(for: key)

        keyChainItem[kSecMatchLimit] = kSecMatchLimitOne
        keyChainItem[kSecReturnData] = kCFBooleanTrue

        var result: AnyObject?

        let status = withUnsafeMutablePointer(to: &result) { pointer in
            self.queue.sync {
                SecItemCopyMatching(keyChainItem as CFDictionary, UnsafeMutablePointer(pointer))
            }
        }
        let userData = UserDefaults.standard.value(forKey: self.userDefaultsPrefix + key) as? Data
        switch status {
            case errSecSuccess:
                guard let data = result as? Data else {
                    return userData
                }
                return data
            default:
                return userData
        }
    }

    /// 清理keychain存放到数据
    /// - Parameter key: key值，如果不传则全部清除
    @discardableResult
    public func delete(for key: String? = nil) -> Any? {
        var keyChainItem = self.create(for: key)
        if let tkey = key {
            if let data = self.value(for: tkey), let value = String(data: data, encoding: .utf8) {
                switch SecItemDelete(keyChainItem as CFDictionary) {
                    case errSecSuccess:
                        if value == chainBoolTrue {
                            return true
                        } else if value == chainBoolFalse {
                            return false
                        } else {
                            return value
                        }
                    default:
                        return nil
                }
            }
            return nil
        } else {
            keyChainItem[kSecMatchLimit] = kSecMatchLimitAll
            keyChainItem[kSecReturnAttributes] = kCFBooleanTrue
            var result: AnyObject?
            let status = withUnsafeMutablePointer(to: &result) { pointer in
                self.queue.sync {
                    SecItemCopyMatching(keyChainItem as CFDictionary, UnsafeMutablePointer(pointer))
                }
            }
            switch status {
                case errSecSuccess:
                    var values = [Any]()
                    if let results = result as? [[CFString: Any]] {
                        for attributes in results {
                            if let account = attributes[kSecAttrAccount] as? String, let data = attributes[kSecValueData] as? Data, let value = String(data: data, encoding: .utf8) {
                                if account != KeyChain.UDIDStringKey {
                                    if value == chainBoolTrue {
                                        values.append(true)
                                    } else if value == chainBoolFalse {
                                        values.append(false)
                                    } else {
                                        values.append(value)
                                    }
                                    let item = self.create(for: account)
                                    self.queue.sync {
                                        let _ = SecItemDelete(item as CFDictionary)
                                    }
                                }
                            }
                        }
                    }
                    return values
                default:
                    return nil
            }
        }
    }

    private var cache: [String: Data] = [:]

    private func create(for key: String? = nil, value: Data? = nil) -> [CFString: Any] {
        var dict = [CFString: Any]()

        dict[kSecClass] = kSecClassGenericPassword
        dict[kSecAttrService] = self.serviceName
        dict[kSecAttrSynchronizable] = self.synchronizable ? kCFBooleanTrue : kCFBooleanFalse

        if let group = self.group, !group.isEmpty {
            dict[kSecAttrAccessGroup] = group
        }
        if let tkey = key {
            dict[kSecAttrAccount] = tkey
        }

        if let tvalue = value {
            dict[kSecValueData] = tvalue
        }

        return dict
    }
}
