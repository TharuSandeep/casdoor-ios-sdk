// Copyright 2021 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Foundation
import AF

public final class Casdoor {
    public init(config: CasdoorConfig) {
        self.config = config
    }
    public let config: CasdoorConfig
    
    var codeVerifier: String!
    var nonce: String!
}

//Apis

extension Casdoor {
    public func getSigninUrl(scope:String? = nil,state:String? = nil) throws -> URL {
        self.codeVerifier = Utils.generateCodeVerifier()
        let url = "\(config.endpoint)login/oauth/authorize"
        self.nonce = Utils.generateNonce()
        let query = CodeRequestQuery.init(config: config, nonce: nonce!, scope: scope, state: state, codeVerifier: codeVerifier!)
        let urlRequst: URLRequest = try .init(url: url, method: .get)
        guard let uri = try query.toUrl(request: urlRequst).url else {
            throw CasdoorError.invalidURL
        }
        return uri
    }
    public func getSignupUrl(
        scope:String? = nil,
        state:String? = nil
    ) throws -> URL {
        let urlString = try getSigninUrl(scope: scope, state: state)
            .absoluteString
            .replacingOccurrences(
                of: "/login/oauth/authorize",
                with: "/signup/oauth/authorize")
        guard let uri = URL.init(string: urlString) else {
            throw CasdoorError.invalidURL
        }
        return uri
    }
    
    public func requestOauthAccessToken(code:String) async throws-> AccessTokenResponse {
        let query = AccessTokenRequest.init(clientID: config.clientID, code: code, verifier: codeVerifier)
        let url = "\(config.apiEndpoint)login/oauth/access_token"
        let token = try await AF.request(url, method: .post, parameters: query, encoder: URLEncodedFormParameterEncoder.default).serializingDecodable(AccessTokenResponse.self).value
        if token.refreshToken == nil {
            throw CasdoorError.init(error: .responseMessage(token.accessToken))
        }
        return token
    }
    
    public func renewToken(refreshToken: String,scope: String? = nil) async throws -> AccessTokenResponse {
        let query = ReNewAccessTokenRequest.init(clientID: config.clientID, scope: scope ?? "read", refreshToken: refreshToken)
        let url = "\(config.apiEndpoint)login/oauth/refresh_token"
        let token = try await AF.request(url, method: .post, parameters: query, encoder: URLEncodedFormParameterEncoder.default).serializingDecodable(AccessTokenResponse.self).value
        if token.refreshToken == nil || token.refreshToken!.isEmpty {
            throw CasdoorError.init(error: .responseMessage(token.accessToken))
        }
        return token
    }
    
    public func logout(idToken: String,state: String? = nil) async throws -> Bool {
        let query = ["id_token_hint":idToken,"state":state ?? config.appName]
        let url = "\(config.apiEndpoint)login/oauth/logout"
        
        let resData = try await AF.request(url, method: .post, parameters: query, encoder: URLEncodedFormParameterEncoder.default).serializingDecodable(CasdoorNoDataResponse.self).value
        try resData.isOk()
        if let isAffected = resData.data,!isAffected.isEmpty {
            return isAffected == "Affected"
        }
        return false
    }
}

extension Casdoor{
    
    public func signUpMobile(body : [String : Any]) async throws{
        var request = URLRequest(url: getLoginUrl())
        
        request.method = .post
        request.setValue("application/json", forHTTPHeaderField: "accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let jsonData = try JSONSerialization.data(withJSONObject: body, options: [])
        request.httpBody = jsonData
        
        AF.request(request)
            .responseDecodable(of: LoginResponse.self) { response in
                   switch response.result {
                   case .success(let loginResponse):
                       print("Login Response: \(loginResponse)")
                   case .failure(let error):
                       print("Error: \(error)")
                   }
               }
     
    }
    
    public func signIn(body : [String : Any]){
        
        var request = URLRequest(url: getLoginUrl())
        
        request.method = .post
        request.setValue("application/json", forHTTPHeaderField: "accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let jsonData = try! JSONSerialization.data(withJSONObject: body, options: [])
        request.httpBody = jsonData
        
        AF.request(request)
            .responseDecodable(of: LoginResponse.self) { response in
                   switch response.result {
                   case .success(let loginResponse):
                       print("Login Response: \(loginResponse)")
                   case .failure(let error):
                       print("Error: \(error)")
                   }
               }
        
    }
    
    private func getLoginUrl() -> URL{
        let url = "\(config.apiEndpoint)login"
        
        let form : [String : String] = [
            "clientId" : config.clientID,
            "responseType" : "code",
            "redirectUri" : config.redirectUri,
            "scope" : "profile",
        ]
        
        var urlComponents = URLComponents(string: url)!
        urlComponents.queryItems = form.map { URLQueryItem(name: $0.key, value: $0.value) }
        
        return  urlComponents.url!
    }
}

struct SignInRequest: Encodable {
    
    let clientId : String
    let responseType : String
    let redirectUri : String
    let scope : String
    
    init(clientId: String, responseType: String = "code", redirectUri: String, scope: String ){
        self.clientId = clientId
        self.responseType = responseType
        self.redirectUri = redirectUri
        self.scope = scope
    }
    enum CodingKeys: String,CodingKey {
        case clientId, responseType, redirectUri, scope
    }
    
}

struct LoginResponse : Decodable {
    let status: String
    let msg: String
    let data : String
    
    func isOk() throws {
        if status == "error" {
            throw CasdoorError.init(error: .responseMessage(msg))
        }
    }
}
