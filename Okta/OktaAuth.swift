/*
 * Copyright (c) 2017, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */
import AppAuth
import Hydra
import Vinculum
import SafariServices

public struct OktaAuthorization {

    func authCodeFlow(_ config: [String: String], _ view: UIViewController) -> Promise<OktaTokenManager> {
        return Promise<OktaTokenManager>(in: .background, { resolve, reject, _ in
            // Discover Endpoints
            guard let issuer = config["issuer"], let clientId = config["clientId"],
                let redirectUri = config["redirectUri"] else {
                    return reject(OktaError.MissingConfigurationValues)
            }

            self.getMetadataConfig(URL(string: issuer))
            .then { oidConfig in
                // Build the Authentication request
                let request = OIDAuthorizationRequest(
                           configuration: oidConfig,
                                clientId: clientId,
                                  scopes: Utils.scrubScopes(config["scopes"]),
                             redirectURL: URL(string: redirectUri)!,
                            responseType: OIDResponseTypeCode,
                    additionalParameters: Utils.parseAdditionalParams(config)
                )

                // Start the authorization flow
                OktaAuth.currentAuthorizationFlow = OIDAuthState.authState(byPresenting: request, presenting: view){
                    authorizationResponse, error in

                    guard let authResponse = authorizationResponse else {
                        return reject(OktaError.APIError("Authorization Error: \(error!.localizedDescription)"))
                    }
                    do {
                        let tokenManager = try OktaTokenManager(authState: authResponse, config: config, validationOptions: nil)

                        // Set the local cache and write to storage
                        self.storeAuthState(tokenManager)
                        return resolve(tokenManager)
                    } catch let error {
                        return reject(error)
                    }
                }
            }
            .catch { error in return reject(error) }
        })
    }

    func passwordFlow(_ config: [String: String], credentials: [String: String]?, _ view: UIViewController) -> Promise<OktaTokenManager> {
        return buildAndPerformTokenRequest(config, additionalParams: credentials)
    }

    func refreshTokensManually(_ config: [String: String], refreshToken: String) -> Promise<OktaTokenManager> {
        return buildAndPerformTokenRequest(config, refreshToken: refreshToken)
    }

    func buildAndPerformTokenRequest(_ config: [String: String], refreshToken: String? = nil, authCode: String? = nil,
                                     additionalParams: [String: String]? = nil) -> Promise<OktaTokenManager> {
        return Promise<OktaTokenManager>(in: .background, { resolve, reject, _ in
            // Discover Endpoints
            guard let issuer = config["issuer"],
                let clientId = config["clientId"],
                let clientSecret = config["clientSecret"],
                let redirectUri = config["redirectUri"] else {
                    return reject(OktaError.MissingConfigurationValues)
            }

            self.getMetadataConfig(URL(string: issuer))
            .then { oidConfig in
                var grantType = OIDGrantTypePassword
                if refreshToken == nil && authCode == nil {
                    // Use the password grant type
                } else {
                    // If there is a refreshToken use the refesh_token grant type
                    // otherwise use the authorization_code grant
                    grantType = refreshToken != nil ? OIDGrantTypeRefreshToken : OIDGrantTypeAuthorizationCode
                }
                // Build the Authentication request
                let request = OIDTokenRequest(
                           configuration: oidConfig,
                               grantType: grantType,
                       authorizationCode: authCode,
                             redirectURL: URL(string: redirectUri)!,
                                clientID: clientId,
                            clientSecret: clientSecret,
                                  scopes: Utils.scrubScopes(config["scopes"]),
                            refreshToken: refreshToken,
                            codeVerifier: nil,
                    additionalParameters: additionalParams
                )

                // Start the authorization flow
                OIDAuthorizationService.perform(request) { authorizationResponse, responseError in
                    if responseError != nil {
                        return reject(OktaError.APIError("Authorization Error: \(responseError!.localizedDescription)"))
                    }

                    if authorizationResponse != nil {
                        let authState = OIDAuthState(
                            authorizationResponse: nil,
                                    tokenResponse: authorizationResponse,
                             registrationResponse: nil
                        )

                        do {
                            let tokenManager = try OktaTokenManager(authState: authState, config: config, validationOptions: nil)

                            // Set the local cache and write to storage
                            self.storeAuthState(tokenManager)
                            return resolve(tokenManager)
                        } catch let error {
                            return reject(error)
                        }
                    }
                }
            }
            .catch { error in return reject(error) }
        })
    }
    
    // In the Future, when AppAuth supports the end session endpoint, this method will not be necessary anymore.
    func logoutFlow(_ config: [String: Any], view:UIViewController, callback: @escaping (OktaError?) -> Void) -> Any? {
        
        let configuration = OktaAuth.tokens?.authState?.lastAuthorizationResponse.request.configuration
        
        guard let endSessionEndpoint = configuration?.discoveryDocument?.discoveryDictionary["end_session_endpoint"] as? String else {
            callback(.apiError(error: "Error: failed to find the end session endpoint."))
            return nil
        }
        
        guard var endSessionURLComponents = URLComponents(string: endSessionEndpoint) else {
            callback(.apiError(error: "Error: Unable to parse End Session Endpoint"))
            return nil
        }
        
        guard let idToken = OktaAuth.tokens?.idToken else {
            callback(.apiError(error: "Error: Unable to get a valid ID Token"))
            return nil
        }
        
        var queryItems = [URLQueryItem(name: "id_token_hint", value: idToken)]
        var scheme:String?
        if let postLogoutRedirectUri = config["post_logout_redirect_uri"] as? String,
            let redirectURLComponents = URLComponents.init(string: postLogoutRedirectUri) {
            scheme = redirectURLComponents.scheme
            queryItems.append(URLQueryItem.init(name: "post_logout_redirect_uri", value: postLogoutRedirectUri))
        }
        endSessionURLComponents.queryItems = queryItems
        
        guard let url = endSessionURLComponents.url else {
            callback(.apiError(error: "Error: Unable to set End Session Endpoint parameters"))
            return nil
        }
        var logoutController:Any?
        if #available(iOS 11.0, *) {
            let session = SFAuthenticationSession(url: url, callbackURLScheme: scheme, completionHandler: { (_, _) in
                callback(nil)
            })
            session.start()
            logoutController = session
        } else {
            let safari = SFSafariViewController.init(url: url)
            view.present(safari, animated: true, completion: {
                callback(nil)
            })
            logoutController = safari
        }
        
        return logoutController
    }


    func getMetadataConfig(_ issuer: URL?) -> Promise<OIDServiceConfiguration> {
        // Get the metadata from the discovery endpoint
        return Promise<OIDServiceConfiguration>(in: .background, { resolve, reject, _ in
            guard let issuer = issuer, let configUrl = URL(string: "\(issuer)/.well-known/openid-configuration") else {
                return reject(OktaError.NoDiscoveryEndpoint)
            }

            OktaApi.get(configUrl, headers: nil)
            .then { response in
                guard let dictResponse = response, let oidcConfig = try? OIDServiceDiscovery(dictionary: dictResponse) else {
                    return reject(OktaError.ParseFailure)
                }
                // Cache the well-known endpoint response
                OktaAuth.wellKnown = dictResponse
                return resolve(OIDServiceConfiguration(discoveryDocument: oidcConfig))
            }
            .catch { error in
                let responseError =
                    "Error returning discovery document: \(error.localizedDescription) Please" +
                    "check your PList configuration"
                return reject(OktaError.APIError(responseError))
            }
        })
    }

    func storeAuthState(_ tokenManager: OktaTokenManager) {
        // Encode and store the current auth state and
        // cache the current tokens
        OktaAuth.tokens = tokenManager

        let authStateData = NSKeyedArchiver.archivedData(withRootObject: tokenManager)
        do {
            try Vinculum.set(key: "OktaAuthStateTokenManager", value: authStateData, accessibility: tokenManager.accessibility)
        } catch let error {
            print("Error: \(error)")
        }
    }
}
