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

public typealias TimerClosure = (_ timer : Int) -> Void
public typealias CasdoorErrorClosure = (_ error : String,_ timer : Int?) -> ()

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
    
    public func signUp(code : String, email: String, name : String, pwd : String, success : @escaping () -> Void, failure : @escaping CasdoorErrorClosure){
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
            failure("Invalid request",nil)
            return
        }
        
        session.request(request)
            .responseString(completionHandler: { string in
                print("response string", string)
            })
            .responseDecodable(of: SignUpResponse.self) { response in
                if let url = request.url{
                    self.cookieHandler.handleCookies(for: response.response, url: url)
                }
                switch response.result {
                case .success(let loginResponse):
                    Task{
                        do {
                            try loginResponse.isOk()
                            success()
                        }catch let timerError as ErrorCodeResponse{
                            failure(timerError.message, timerError.timeout)
                        }catch let error as CasdoorError{
                            failure(error.description,nil)
                        }catch{
                            failure(error.localizedDescription,nil)
                        }
                    }
                case .failure(let error):
                    failure(error.errorDescription ?? "", nil)
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
    
    public func confirmSocialMediaLinking<T : Decodable>(consentToken : String, success : @escaping (T) -> Void, failure : @escaping (Error) -> Void){
        var request = URLRequest(url: getConfirmAuthUrl())
        cookieHandler.applyCookies(for: &request)
        
        let body : [String : Any] = [
            "confirmed"     : true,
            "consentToken"  : consentToken
        ]
        
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
    
    private func getConfirmAuthUrl() -> URL{
        let url = "\(config.apiEndpoint)confirm-oauth-link"
        
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
        captchaToken: String,
        clientSecret: String,
        captchaType: String,
        type: MfaType = .email,
        success : @escaping TimerClosure,
        failure : @escaping CasdoorErrorClosure
    ) {
        self.getEmailAndPhone(
            email: dest,
            captchaToken: captchaToken,
            clientSecret: clientSecret,
            captchaType: captchaType,
            success: success,
            failure: failure
        )
    }

    private func getEmailAndPhone(
        email: String,
        captchaToken: String,
        clientSecret: String,
        captchaType: String,
        success: @escaping TimerClosure,
        failure: @escaping CasdoorErrorClosure
    ) {
        let url = "\(config.apiEndpoint)get-email-and-phone"
        
        let encodedEmail = email.stringByAddingPercentEncodingForRFC3986()
        let fullUrl = url + "?organization=\(config.organizationName)&username=\(encodedEmail ?? email)"
        
        var urlComponents = URLComponents(string: fullUrl)!
        
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
                switch response.result {
                case .success(let loginResponse):
                    Task{
                        do {
                            try loginResponse.isOk()
                            
                            self.sendVerificationCode(
                                dest: email,
                                method: "forget",
                                type : "email",
                                captchaToken: captchaToken,
                                clientSecret: clientSecret,
                                captchaType: captchaType
                            ) { timer in
                                success(timer)
                            } failure: { message, timer in
                                failure(message, timer)
                            }
                        }catch let error as CasdoorError{
                            failure(error.description, nil)
                        }catch{
                            failure(error.localizedDescription, nil)
                        }
                    }
                case .failure(let error):
                    failure(error.errorDescription ?? "", nil)
                }
            }
    }
    
    public func sendVerificationCode(
        dest: String,
        method: String,
        type: String,
        captchaToken: String,
        clientSecret: String,
        captchaType: String,
        success: @escaping TimerClosure,
        failure: @escaping CasdoorErrorClosure
    ) {

        let endPoint = Endpoint.verficationCode(
            appName: config.appName,
            dest: dest,
            method: method,
            type: type,
            captchaToken: captchaToken,
            clientSecret: clientSecret,
            captchaType: captchaType
        )
        guard let request = endPoint.getRequest(endPoint: config.apiEndpoint, cookieHandler: self.cookieHandler),
              let session = session else {
            failure("Invalid request",nil)
            return
        }
        session.request(request)
            .responseString(completionHandler: { string in
                print("response string", string)
            })
            .responseDecodable(of: SendVerificationCodeResponse.self) { response in
                if let url = request.url{
                    self.cookieHandler.handleCookies(for: response.response, url: url)
                }
                switch response.result {
                case .success(let s):
                    print("send verification code ", s)
                    //                    if method == "signup" || method == "forget"{
                    Task{
                        do {
                            try s.isOk()
                            if let data2 = s.data2{
                                switch data2{
                                case .int(let int):
                                    success(int)
                                case .errorCode(let timerError):
                                    success(timerError.timeout)
                                }
                            }else{
                                success(0)
                            }
                        }catch let timerError as ErrorCodeResponse{
                            failure(timerError.message, timerError.timeout)
                        }catch let error as CasdoorError{
                            failure(error.description,nil)
                        }catch{
                            failure(error.localizedDescription,nil)
                        }
                    }
                    //                    }else{
                    //                        success()
                    //                    }
                case .failure(let error):
                    failure(error.errorDescription ?? "", nil)
                }
            }
    }
    
    public func verifyCode(email : String, code : String, success : @escaping () -> Void, failure : @escaping CasdoorErrorClosure){
        
        let endPoint = Endpoint.verifyCode(appName: config.appName, organizationName: config.organizationName, email: email, code: code)
        
        guard let request = endPoint.getRequest(endPoint: config.apiEndpoint, cookieHandler: self.cookieHandler),
              let session = session
        else{
            failure("Invalid request", nil)
            return
        }
        
        session.request(request)
            .responseString(completionHandler: { string in
                print("response string", string)
            })
            .responseDecodable(of: VerifyCodeResponse.self) { response in
                if let url = request.url{
                    self.cookieHandler.handleCookies(for: response.response, url: url)
                }
                switch response.result {
                case .success(let verifyCodeResponse):
                    Task{
                        do {
                            try verifyCodeResponse.isOk()
                            success()
                        }catch let timerError as ErrorCodeResponse{
                            failure(timerError.message, timerError.timeout)
                        }catch let error as CasdoorError{
                            failure(error.description,nil)
                        }catch{
                            failure(error.localizedDescription,nil)
                        }
                    }
                case .failure(let error):
                    failure(error.errorDescription ?? "",nil)
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
// MARK: - Captcha
extension Casdoor {
    public func getCaptcha(
        success: @escaping (GetCaptchaData?) -> Void,
        failure: @escaping (String) -> Void
    ) {
        let endPoint = Endpoint.getCaptcha()
        guard let request = endPoint.getRequest(endPoint: config.apiEndpoint),
              let session = session else {
            failure("Invalid request")
            return
        }
        session.request(request)
            .responseString(completionHandler: { string in
                print("response string", string)
            })
            .responseDecodable(of: GetCaptchaesponse.self) { response in
                if let url = request.url{
                    self.cookieHandler.handleCookies(for: response.response, url: url)
                }
                switch response.result {
                case .success(let result):
                    print("send verification code ", result)
                    //                    if method == "signup" || method == "forget"{
                    Task{
                        do {
                            try result.isOk()
                            if let data = result.data{
                                success(data)
                            }else{
                                success(nil)
                            }
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
 // MARK: - responses
public struct LoginResponse: Decodable {
    public let status: String
    public let msg: String
    public let data: LoginDataWrapper?
    public let data2: LoginData2Wrapper?

    // Custom Decodable implementation
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        self.status = try container.decode(String.self, forKey: .status)
        self.msg = try container.decode(String.self, forKey: .msg)
//        self.data = try container.decodeIfPresent(String.self, forKey: .data)
        
        if let stringValue = try? container.decode(String.self, forKey: .data) {
            self.data = .string(stringValue)
        }else if let objectValue = try? container.decode(LoginData.self, forKey: .data){
            self.data = .object(objectValue)
        }else{
            self.data = nil
        }

        if let boolValue = try? container.decode(Bool.self, forKey: .data2) {
            self.data2 = .boolean(boolValue)
        }else if let stringValue = try? container.decode(String.self, forKey: .data2) {
            self.data2 = .string(stringValue)
        }else if let arrayValue = try? container.decode([LoginData2].self, forKey: .data2) {
            self.data2 = .array(arrayValue)
        }else if let errorValue = try? container.decode(ErrorCodeResponse.self, forKey: .data2) {
            self.data2 = .errorCode(errorValue)
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
    public enum LoginData2Wrapper {
        case boolean(Bool)
        case string(String)
        case array([LoginData2])
        case errorCode(ErrorCodeResponse)
    }
}

public enum LoginDataWrapper{
    case string(String)
    case object(LoginData)
}

private enum CodingKeys: String, CodingKey {
    case status
    case msg
    case data
    case data2
}

public struct LoginData : Decodable{
    public let MfaChallengeCode : String?
    public let MfaState : String?
}

public struct LoginData2 : Decodable{
    public let enabled : Bool
    public let isPreferred : Bool
    public let mfaType : String
    public let secret,countryCode : String?
}

public struct SignUpResponse : Decodable{
    public let status: String
    public let msg: String
    public let data : String?
    public let data2 : AuthCodeData2Wrapper?
    
    func isOk() throws {
        if status == "error" {
            switch data2 {
            case .errorCode(let errorCodeResponse):
                throw errorCodeResponse
            default :
                throw CasdoorError.init(error: .responseMessage(msg))
            }
        }
    }
    
    public enum AuthCodeData2Wrapper : Codable {
        case boolean(Bool)
        case errorCode(ErrorCodeResponse)
        case empty(EmptyResponse)
        
        public init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            if let boolValue = try? container.decode(Bool.self) {
                self = .boolean(boolValue)
            } else if let errorValue = try? container.decode(ErrorCodeResponse.self) {
                self = .errorCode(errorValue)
            } else if let emptyValue = try? container.decode(EmptyResponse.self){
                self = .empty(emptyValue)
            }else {
                throw DecodingError.typeMismatch(
                    AuthCodeData2Wrapper.self,
                    DecodingError.Context(
                        codingPath: decoder.codingPath,
                        debugDescription: "Expected Int or ErrorCodeResponse."
                    )
                )
            }
        }
        
        public func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            switch self {
            case .boolean(let value):
                try container.encode(value)
            case .errorCode(let value):
                try container.encode(value)
            case .empty(let value):
                try container.encode(value)
            }
        }
    }
}

public struct AuthCodeResponse : Codable{
    
    public let status: String
    public let msg: String
    public let data : String?
    public let data2 : AuthCodeData2Wrapper?
    
    public func isOk() throws {
        if status == "error" {
            switch data2 {
            case .errorCode(let errorCodeResponse):
                throw errorCodeResponse
            default :
                throw CasdoorError.init(error: .responseMessage(msg))
            }
        }
    }
    
    public enum AuthCodeData2Wrapper : Codable {
        case boolean(Bool)
        case errorCode(ErrorCodeResponse)
        case empty(EmptyResponse)
        case requireConsent(RequireConsentResponse)
        
        public init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            if let boolValue = try? container.decode(Bool.self) {
                self = .boolean(boolValue)
            } else if let errorValue = try? container.decode(ErrorCodeResponse.self) {
                self = .errorCode(errorValue)
            }else if let requireConsentValue = try? container.decode(RequireConsentResponse.self){
                self = .requireConsent(requireConsentValue)
            } else if let emptyValue = try? container.decode(EmptyResponse.self){
                self = .empty(emptyValue)
            } 
            else {
                throw DecodingError.typeMismatch(
                    AuthCodeData2Wrapper.self,
                    DecodingError.Context(
                        codingPath: decoder.codingPath,
                        debugDescription: "Expected Int or ErrorCodeResponse."
                    )
                )
            }
        }
        
        public func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            switch self {
            case .boolean(let value):
                try container.encode(value)
            case .errorCode(let value):
                try container.encode(value)
            case .empty(let value):
                try container.encode(value)
            case .requireConsent(let value):
                try container.encode(value)
            }
        }
    }
}

public struct EmptyResponse : Codable{
    
}

public struct ErrorCodeResponse : Codable, Error{
    public let errorCode : String
    public let message : String
    public let timeout : Int
}

public struct RequireConsentResponse: Codable {
    public let requiresConsent: Bool
    public let email: String
    public let providerType: String
    public let providerId: String
    public let userId: String
    public let userName: String
    public let userDisplayName: String
    public let consentToken: String
    public let application: String
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

public struct GetCaptchaData: Codable {
    public let type, clientId, clientSecret: String?

    public func isTurnstileEnabled() -> Bool {
        guard let type, !type.isEmpty,
              let clientId, !clientId.isEmpty else { return false }
        return true
    }
}


// MARK: - Send verification code
struct SendVerificationCodeResponse: Codable {
   
    let status, msg : String
    let sub, name: String?
    let data: EmailAndPhoneData?
    let data2: SendVerificationCodeData2Wrapper?
    
    func isOk() throws {
        if status == "error" {
            switch data2 {
            case .errorCode(let errorCodeResponse):
                throw errorCodeResponse
            default :
                throw CasdoorError.init(error: .responseMessage(msg))
            }
        }
    }
    
    public enum SendVerificationCodeData2Wrapper: Codable {
        case int(Int)
        case errorCode(ErrorCodeResponse)

        public init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            if let intValue = try? container.decode(Int.self) {
                self = .int(intValue)
            } else if let errorValue = try? container.decode(ErrorCodeResponse.self) {
                self = .errorCode(errorValue)
            } else {
                throw DecodingError.typeMismatch(
                    SendVerificationCodeData2Wrapper.self,
                    DecodingError.Context(
                        codingPath: decoder.codingPath,
                        debugDescription: "Expected Int or ErrorCodeResponse."
                    )
                )
            }
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            switch self {
            case .int(let value):
                try container.encode(value)
            case .errorCode(let value):
                try container.encode(value)
            }
        }
    }

}

struct GetCaptchaesponse: Codable {
    let status, msg : String
    let sub, name: String?
    let data: GetCaptchaData?
    let data2: VerifyCodeData2Wrapper?

    func isOk() throws {
        if status == "error" {
            switch data2 {
            case .errorCode(let errorCodeResponse):
                throw errorCodeResponse
            default :
                throw CasdoorError.init(error: .responseMessage(msg))
            }
        }
    }

    public enum SendVerificationCodeData2Wrapper: Codable {
        case int(Int)
        case errorCode(ErrorCodeResponse)

        public init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            if let intValue = try? container.decode(Int.self) {
                self = .int(intValue)
            } else if let errorValue = try? container.decode(ErrorCodeResponse.self) {
                self = .errorCode(errorValue)
            } else {
                throw DecodingError.typeMismatch(
                    SendVerificationCodeData2Wrapper.self,
                    DecodingError.Context(
                        codingPath: decoder.codingPath,
                        debugDescription: "Expected Int or ErrorCodeResponse."
                    )
                )
            }
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            switch self {
            case .int(let value):
                try container.encode(value)
            case .errorCode(let value):
                try container.encode(value)
            }
        }
    }

}

//MARK: VerifyCodeResponse
struct VerifyCodeResponse : Codable{
    public let status: String
    public let msg: String
    public let data : String?
    public let data2 : VerifyCodeData2Wrapper?
    
    public func isOk() throws {
        if status == "error" {
            switch data2 {
            case .errorCode(let errorCodeResponse):
                throw errorCodeResponse
            default :
                throw CasdoorError.init(error: .responseMessage(msg))
            }
        }
    }
    
}

public enum VerifyCodeData2Wrapper : Codable {
    case string(String)
    case errorCode(ErrorCodeResponse)
    case empty(EmptyResponse)

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let stringValue = try? container.decode(String.self) {
            self = .string(stringValue)
        } else if let errorValue = try? container.decode(ErrorCodeResponse.self) {
            self = .errorCode(errorValue)
        } else if let emptyValue = try? container.decode(EmptyResponse.self){
            self = .empty(emptyValue)
        }else {
            throw DecodingError.typeMismatch(
                VerifyCodeData2Wrapper.self,
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Expected Int or ErrorCodeResponse."
                )
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let value):
            try container.encode(value)
        case .errorCode(let value):
            try container.encode(value)
        case .empty(let value):
            try container.encode(value)
        }
    }
}
