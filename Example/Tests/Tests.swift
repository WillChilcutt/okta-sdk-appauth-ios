import UIKit
import XCTest
@testable import OktaAuth

class Tests: XCTestCase {

    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
    }

    func testPListFailure() {
        // Attempt to find a plist file that does not exist
        XCTAssertNil(Utils.getPlistConfiguration(forResourceName: "noFile"))
    }

    func testPListFound() {
        // Attempt to find the Okta.plist file
        XCTAssertNotNil(Utils.getPlistConfiguration())
    }

    func testPListFormatWithTrailingSlash() {
        // Validate the PList issuer
        let dict = [
            "issuer": "https://example.com/oauth2/authServerId/"
        ]
        let issuer = Utils.removeTrailingSlash(dict["issuer"]!)
        XCTAssertEqual(issuer, "https://example.com/oauth2/authServerId")
    }

    func testPListFormatWithoutTrailingSlash() {
        // Validate the PList issuer
        let dict = [
            "issuer": "https://example.com/oauth2/authServerId"
        ]
        let issuer = Utils.removeTrailingSlash(dict["issuer"]!)
        XCTAssertEqual(issuer, "https://example.com/oauth2/authServerId")
    }

    func testValidScopesArray() {
        // Validate the scopes are in the correct format
        let scopes = ["openid"]
        let scrubbedScopes = Utils.scrubScopes(scopes)
        XCTAssertEqual(scrubbedScopes, scopes)
    }

    func testValidScopesString() {
        // Validate the scopes are in the correct format
        let scopes = "openid profile email"
        let validScopes = ["openid", "profile", "email"]
        let scrubbedScopes = Utils.scrubScopes(scopes)
        XCTAssertEqual(scrubbedScopes, validScopes)
    }

    func testInvalidScopes() {
        // Validate that scopes of wrong type will still return valid scopes
        let scopes = [1, 2, 3]
        XCTAssertEqual(Utils.scrubScopes(scopes).first, "openid")
    }

    func testPasswordFailureFlow() {
        // Validate the username & password flow fails without clientSecret
        _ = Utils.getPlistConfiguration(forResourceName: "Okta-PasswordFlow")

        let pwdExpectation = expectation(description: "Will error attempting username/password auth")

        OktaAuth
            .login("user@example.com", password: "password")
            .start(withPListConfig: "Okta-PasswordFlow", view: UIViewController()) { response, error in
                XCTAssertEqual(
                    error!.localizedDescription,
                    "Authorization Error: The operation couldn’t be completed. (org.openid.appauth.general error -6.)"
                )
                pwdExpectation.fulfill()
        }

        waitForExpectations(timeout: 3, handler: { error in
            // Fail on timeout
            if error != nil { XCTFail(error!.localizedDescription) }
       })
    }

    func testKeychainStorage() {
        // Validate that tokens can be stored and retrieved via the keychain
        let tokens = OktaTokenManager(authState: nil)

        tokens.set(value: "fakeToken", forKey: "accessToken")
        XCTAssertEqual(tokens.get(forKey: "accessToken"), "fakeToken")

        // Clear tokens
        tokens.clear()
        XCTAssertNil(tokens.get(forKey: "accessToken"))
    }

    func testBackgroundKeychainStorage() {
        // Validate that tokens can be stored and retrieved via the keychain
        let tokens = OktaTokenManager(authState: nil)

        tokens.set(value: "fakeToken", forKey: "accessToken", needsBackgroundAccess: true)
        XCTAssertEqual(tokens.get(forKey: "accessToken"), "fakeToken")

        // Clear tokens
        tokens.clear()
        XCTAssertNil(tokens.get(forKey: "accessToken"))
    }

    func testIntrospectionEndpointURL() {
        // Similar use case for revoke and userinfo endpoints
        OktaAuth.configuration = [
            "issuer": "https://example.com"
        ]
        let url = Introspect().getIntrospectionEndpoint()
        XCTAssertEqual(url?.absoluteString, "https://example.com/oauth2/v1/introspect")
    }

    func testIntrospectionEndpointURLWithOAuth2() {
        // Similar use case for revoke and userinfo endpoints
        OktaAuth.configuration = [
            "issuer": "https://example.com/oauth2/default"
        ]
        let url = Introspect().getIntrospectionEndpoint()
        XCTAssertEqual(url?.absoluteString, "https://example.com/oauth2/default/v1/introspect")
    }
}
