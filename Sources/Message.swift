//
//  Message.swift
//  SwiftyRSA
//
//  Created by Loïs Di Qual on 9/19/16.
//  Copyright © 2016 Scoop. All rights reserved.
//

import Foundation

public protocol Message {
    // MARK: Lifecycle
    init(data: Data)
    init(base64Encoded base64String: String) throws

    // MARK: Internal
    var data: Data { get }
    var base64String: String { get }
}

public extension Message {
    // MARK: Lifecycle

    /// Creates an encrypted message with a base64-encoded string.
    ///
    /// - Parameter base64String: Base64-encoded data of the encrypted message
    /// - Throws: SwiftyRSAError
    init(base64Encoded base64String: String) throws {
        guard let data = Data(base64Encoded: base64String) else {
            throw SwiftyRSAError.invalidBase64String
        }
        self.init(data: data)
    }

    // MARK: Internal

    /// Base64-encoded string of the message data
    var base64String: String {
        return data.base64EncodedString()
    }
}
