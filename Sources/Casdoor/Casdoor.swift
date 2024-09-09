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
    
    public var codeVerifier: String!
    var nonce: String!
    
    var session : Session?
    var cookieHandler = CustomCookieHandler()
}

class SimpleCookieJar: HTTPCookieStorage {
    private var cookieStore: [String: [HTTPCookie]] = [:]

    override func setCookies(_ cookies: [HTTPCookie], for URL: URL?, mainDocumentURL: URL?) {
        guard let host = URL?.host else { return }
        cookieStore[host] = cookies
    }

    override func cookies(for URL: URL?) -> [HTTPCookie]? {
        guard let host = URL?.host else { return nil }
        return cookieStore[host]
    }
}

class CustomCookieHandler {
    
    private let cookieJar = SimpleCookieJar()
    
    func setupSession() -> Session {
        let configuration = URLSessionConfiguration.default
        configuration.httpCookieStorage = HTTPCookieStorage.shared
        let session = Session(configuration: configuration)
        return session
    }
    
    func handleCookies(for response: URLResponse?, url: URL) {
        guard let httpResponse = response as? HTTPURLResponse,
              let headerFields = httpResponse.allHeaderFields as? [String: String] else {
            return
        }
        let cookies = HTTPCookie.cookies(withResponseHeaderFields: headerFields, for: url)
        cookieJar.setCookies(cookies, for: url, mainDocumentURL: nil)
        cookies.forEach { HTTPCookieStorage.shared.setCookie($0) }
    }
    func applyCookies(for request: inout URLRequest) {
        guard let cookies = cookieJar.cookies(for: request.url) else {
            return
        }
        let headers = HTTPCookie.requestHeaderFields(with: cookies)
        request.allHTTPHeaderFields = headers
    }
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
    
    public func signUp(code : String, email: String, name : String, pwd : String, success : @escaping () -> Void, failure : @escaping (String) -> ()){
        let endPoint = Endpoint.signUp(
            appName: config.appName,
            code: code,
            organizationName: config.organizationName,
            email: email,
            name: name,
            pwd: pwd,
            config: config,
            codeVerifier: self.codeVerifier)
        guard let request = endPoint.getRequest(endPoint: config.apiEndpoint, cookieHandler: self.cookieHandler),
              let session = session
        else{
            failure("Invalid request")
            return
        }
        
        session.request(request)
            .responseString(completionHandler: { string in
                print("response string", string)
            })
            .responseDecodable(of: DefaultResponse.self) { response in
                if let url = request.url{
                    self.cookieHandler.handleCookies(for: response.response, url: url)
                }
                switch response.result {
                case .success(let loginResponse):
                    Task{
                        do {
                            try loginResponse.isOk()
                            success()
                        }catch let error as CasdoorError{
                            failure(error.description)
                        }catch{
                            failure(error.localizedDescription)
                        }
                    }
                case .failure(let error):
                    print("Error: \(error)")
                }
            }
    }
    
    public func loginAfterSignUp(success : @escaping (String) -> Void, failure : @escaping (String) -> ()){
        
        let endPoint = Endpoint.continueSignUp(config: config, codeVerifier: self.codeVerifier)
        guard let request = endPoint.getRequest(endPoint: config.apiEndpoint, cookieHandler: self.cookieHandler),
              let session = session
        else{
            failure("Invalid request")
            return
        }
        
        session.request(request)
            .responseString(completionHandler: { string in
                print("response string", string)
            })
            .responseDecodable(of: AuthCodeResponse.self) { response in
                if let url = request.url{
                    self.cookieHandler.handleCookies(for: response.response, url: url)
                }
                switch response.result {
                case .success(let loginResponse):
                    Task{
                        do {
                            try loginResponse.isOk()
                            success(loginResponse.data ?? "")
                        }catch let error as CasdoorError{
                            failure(error.description)
                        }catch{
                            failure(error.localizedDescription)
                        }
                    }
                case .failure(let error):
                    print("Error: \(error)")
                }
            }
    }
    
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
    
    public func signIn<T : Decodable>(body : [String : Any] , success : @escaping (T) -> (), failure : @escaping (Error) -> ()){
        self.setupSession()
        var request = URLRequest(url: getLoginUrl())
        cookieHandler.applyCookies(for: &request)
        
        request.method = .post
        request.setValue("application/json", forHTTPHeaderField: "accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        do {
            let jsonData = try JSONSerialization.data(withJSONObject: body, options: [])
            request.httpBody = jsonData
        } catch {
            print("Failed to serialize JSON: \(error)")
            return
        }
        
        guard let session = session else {
            print("session is empty")
            return
        }
        
        
        
        session.request(request)
            .responseString(completionHandler: { string in
                print(string)
            })
            .responseDecodable(of: T.self) { response in
                if let url = request.url{
                    self.cookieHandler.handleCookies(for: response.response, url: url)
                }
                switch response.result {
                case .success(let loginResponse):
                    success(loginResponse)
                    print("Login Response: \(loginResponse)")
                case .failure(let error):
                    failure(error)
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
            "code_challenge_method" : "S256",
            "code_challenge" : Utils.generateCodeChallenge(self.codeVerifier)
        ]
        
        var urlComponents = URLComponents(string: url)!
        urlComponents.queryItems = form.map { URLQueryItem(name: $0.key, value: $0.value) }
        
        return  urlComponents.url!
    }
    
    public func setupSession(){
        
        session = cookieHandler.setupSession()
        
        self.codeVerifier = Utils.generateCodeVerifier()
        self.nonce = Utils.generateNonce()
    }
}

//MARK: - forget password
extension Casdoor{
    public func forgotPassword(
        dest: String,
        type: MfaType = .email,
        success : @escaping () -> Void,
        failure : @escaping (String) -> ()
    ) {
        
        self.sendVerificationCode(dest: dest, method: "forget",type: type.rawValue) {
            success()
        } failure: { message in
            failure(message)
        }
//        self.getEmailAndPhone(email : dest)
    }
    /* not needed for now
    private func getEmailAndPhone(email : String, success : @escaping () -> Void, failure : @escaping (String) -> ()){
        let url = "\(config.apiEndpoint)get-email-and-phone"
        
        let form : [String : String] = [
            "organization" : config.organizationName,
            "username" : email
        ]
        
        var urlComponents = URLComponents(string: url)!
        urlComponents.queryItems = form.map { URLQueryItem(name: $0.key, value: $0.value) }
        
        var request = URLRequest(url: urlComponents.url!)
        cookieHandler.applyCookies(for: &request)
        
        request.method = .get
        request.setValue("application/json", forHTTPHeaderField: "accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        guard let session = session else {
            print("session is empty")
            return
        }
        
        session.request(request)
            .responseDecodable(of: EmailAndPhoneResponse.self) { response in
                self.cookieHandler.handleCookies(for: response.response, url: urlComponents.url!)
                self.sendVerificationCode(dest: email, method: "forget", type : "email") {
                    success()
                } failure: { message in
                    failure(message)
                }

               }
    }
    */
    public func sendVerificationCode(dest : String, method : String, type : String , success : @escaping () -> Void, failure : @escaping (String) -> ()){
        
        let endPoint = Endpoint.verficationCode(appName: config.appName, dest: dest, method: method, type: type)
        guard let request = endPoint.getRequest(endPoint: config.apiEndpoint, cookieHandler: self.cookieHandler),
              let session = session
        else{
            failure("Invalid request")
            return
        }
        session.request(request)
            .responseString(completionHandler: { string in
                print("response string", string)
            })
            .responseDecodable(of: EmailAndPhoneResponse.self) { response in
                if let url = request.url{
                    self.cookieHandler.handleCookies(for: response.response, url: url)
                }
                switch response.result {
                case .success(let s):
                    print("send verification code ", s)
                    if method == "signup" || method == "forget"{
                        Task{
                            do {
                                try s.isOk()
                                success()
                            }catch let error as CasdoorError{
                                failure(error.description)
                            }catch{
                                failure(error.localizedDescription)
                            }
                        }
                    }else{
                        success()
                    }
                case .failure(let error):
                    failure(error.errorDescription ?? "")
                }
            }
    }
    
    public func verifyCode(email : String, code : String, success : @escaping () -> Void, failure : @escaping (String) -> ()){
        
        let endPoint = Endpoint.verifyCode(appName: config.appName, organizationName: config.organizationName, email: email, code: code)
        
        guard let request = endPoint.getRequest(endPoint: config.apiEndpoint, cookieHandler: self.cookieHandler),
              let session = session
        else{
            failure("Invalid request")
            return
        }
        
        session.request(request)
            .responseDecodable(of: CasdoorNoDataResponse.self) { response in
                if let url = request.url{
                    self.cookieHandler.handleCookies(for: response.response, url: url)
                }
                switch response.result {
                case .success(let loginResponse):
                    Task{
                        do {
                            try loginResponse.isOk()
                            success()
                        }catch let error as CasdoorError{
                            failure(error.description)
                        }catch{
                            failure(error.localizedDescription)
                        }
                    }
                case .failure(let error):
                    failure(error.errorDescription ?? "")
                }
            }

    }
    
    public func setPassword(email : String,pwd : String, code : String, success : @escaping () -> Void, failure : @escaping (String) -> ()){
        
        let endPoint = Endpoint.setPassword(organizationName: config.organizationName, email: email, pwd: pwd, code: code)
        
        guard let request = endPoint.getRequest(endPoint: config.apiEndpoint, cookieHandler: self.cookieHandler),
              let session = session
        else{
            failure("Invalid request")
            return
        }
        
        session.request(request)
            .responseDecodable(of: CasdoorNoDataResponse.self) { response in
                if let url = request.url{
                    self.cookieHandler.handleCookies(for: response.response, url: url)
                }
                switch response.result {
                case .success(let loginResponse):
                    Task{
                        do {
                            try loginResponse.isOk()
                            success()
                        }catch let error as CasdoorError{
                            failure(error.description)
                        }catch{
                            failure(error.localizedDescription)
                        }
                    }
                case .failure(let error):
                    failure(error.errorDescription ?? "")
                }
            }
    }
}

//MARK: - helper functions
extension Casdoor{
    
    
    // Helper function to create boundary string
    func generateBoundary() -> String {
        return "Boundary-\(UUID().uuidString)"
    }

    // Helper function to create body data
    func createBody(with parameters: [String: String]?, boundary: String) -> Data {
        var body = Data()

        if let parameters = parameters {
            for (key, value) in parameters {
                body.appendString("--\(boundary)\r\n")
                body.appendString("Content-Disposition: form-data; name=\"\(key)\"\r\n\r\n")
                body.appendString("\(value)\r\n")
            }
        }

        body.appendString("--\(boundary)--\r\n")
        return body
    }
}

// Extension to append string to Data
extension Data {
    mutating func appendString(_ string: String) {
        if let data = string.data(using: .utf8) {
            append(data)
        }
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

public struct LoginResponse: Decodable {
    public let status: String
    public let msg: String
    public let data: String?
    public let data2: Data2Wrapper?

    // Custom Decodable implementation
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        self.status = try container.decode(String.self, forKey: .status)
        self.msg = try container.decode(String.self, forKey: .msg)
        self.data = try container.decodeIfPresent(String.self, forKey: .data)

        if let boolValue = try? container.decode(Bool.self, forKey: .data2) {
            self.data2 = .boolean(boolValue)
        } else if let arrayValue = try? container.decode([LoginData2].self, forKey: .data2) {
            self.data2 = .array(arrayValue)
        } else {
            self.data2 = nil
        }
    }

    public func isOk() throws {
        if status == "error" {
            throw CasdoorError.init(error: .responseMessage(msg))
        }

        if data2 == nil {
            throw CasdoorError.init(error: .responseMessage("data2 is missing or invalid"))
        }
    }

    // Enum to define the possible types for data2
    public enum Data2Wrapper {
        case boolean(Bool)
        case array([LoginData2])
    }

    private enum CodingKeys: String, CodingKey {
        case status
        case msg
        case data
        case data2
    }
}

public struct LoginData2 : Decodable{
    public let enabled : Bool
    public let isPreferred : Bool
    public let mfaType : String
    public let secret,countryCode : String?
}

public struct DefaultResponse : Decodable{
    public let status: String
    public let msg: String
    public let data : String?
    public let data2 : Bool?
    
    func isOk() throws {
        if status == "error" {
            throw CasdoorError.init(error: .responseMessage(msg))
        }
    }
}

public struct AuthCodeResponse : Decodable{
    public let status: String
    public let msg: String
    public let data : String?
    public let data2 : Bool?
    
    public func isOk() throws {
        if status == "error" {
            throw CasdoorError.init(error: .responseMessage(msg))
        }
    }
}

// MARK: - Welcome
struct EmailAndPhoneResponse: Codable {
    let status, msg : String
    let sub, name: String?
    let data: EmailAndPhoneData?
    let data2: String?
    
    func isOk() throws {
        if status == "error" {
            throw CasdoorError.init(error: .responseMessage(msg))
        }
    }
}

// MARK: - DataClass
struct EmailAndPhoneData: Codable {
    let name, email: String
}
