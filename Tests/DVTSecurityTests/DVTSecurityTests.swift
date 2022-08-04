@testable import DVTSecurity
import XCTest

final class DVTSecurityTests: XCTestCase {
    func testExample() throws {
        func testRSA() throws {
            let strPuk = """
            -----BEGIN PUBLIC KEY-----
            MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDA7MgpTUMWLvAShQqvEFjmdvC0
            NOMkzCLi1iodZJpWeAzo14GSSXlQtCatjeJBI6G9b0tj4Kdv02c7kCjcOehPL7xy
            m2y06F23konbmJVq3KR1jJS8Xx5OjC40vUJcDiWqw0/ScvYLpD+OQyUiVfwDNttR
            FI3w2Zm+9PPOz4SEYQIDAQAB
            -----END PUBLIC KEY-----
            """

            let strPrk = """
            -----BEGIN PRIVATE KEY-----
            MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMDsyClNQxYu8BKF
            Cq8QWOZ28LQ04yTMIuLWKh1kmlZ4DOjXgZJJeVC0Jq2N4kEjob1vS2Pgp2/TZzuQ
            KNw56E8vvHKbbLToXbeSiduYlWrcpHWMlLxfHk6MLjS9QlwOJarDT9Jy9gukP45D
            JSJV/AM221EUjfDZmb70887PhIRhAgMBAAECgYEAoAOEXSVVEFAsFOA+JUeExNo/
            +OeowjuCb+w8EBcCH9gAtRsRwBiqw3I4Zli5IVgBbZKi0BtkJM8N34xJJ6fr8lje
            b/csavQDudSWT2GwQnsRpSsppE5XWeFmYiexr6X9OneKz0OG9RwrM2wMEwgAMlpc
            N7QO5RmngamjDGAmJVUCQQDoL5KbUI8rg9mTuIo4AA8Y29mjgzTse/Cp4TsSXFAm
            xOWqusaOLOgnfcUiLxswm13W+55ZXij6wfXLkxqbNK93AkEA1LZZO3HIFJjigEF6
            LmnoJt+FJ45wksT9nu7plEZAsMtU/VrMids3PlgE71L9jVwdGqsPAVQkkl7FX9ro
            oENQ5wJAP5qwna1u2uvOkaHu8zJI8HVhZGKP/+xf3BmgFgKFzmkHxUJPHCl/Gzpf
            42JmH2WgSkE5ep/JuA+kJrVQh43iNwJAGs2HXOgvb/j7wXF+tc5+hDdyDdPy92t/
            EcHFCPv5Ns3IPcxtLYnD4kUxCf8JGADdYfjgASjbGt56PGPXICqbTQJBAONhj5kl
            JPgCF4suHpFLrHFm5AFr7GCG0MnuDFAnmGTkvpu8oZQkUy2mpu6Fi0HOMaq9JcFJ
            vd4U3Xn5koBpAAQ=
            -----END PRIVATE KEY-----
            """
            let encryptString = "你好"
            let encrypt = try? encryptString.rsa.encrypt(strPuk)
            let decrypt = try? encrypt?.rsa.decrypt(strPrk)

            print("encrypt:", encrypt as Any, "\ndecrypt:", decrypt as Any)
            XCTAssertEqual(decrypt, encryptString)
            let signed = "123"
            do {
                let signature = try signed.rsa.signed(strPrk)
                print(signature)
                let res = try signed.rsa.verify(strPuk, signature: signature)
                XCTAssertTrue(res)
            } catch let error {
                print(error)
            }
        }
    }
}
