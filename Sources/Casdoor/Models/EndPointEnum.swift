//
//  File.swift
//  
//
//  Created by Sandeep Tharu on 19/08/2024.
//

import Foundation
import AF

public enum Endpoint{
    
    case verficationCode(appName : String,dest : String,method : String,type : String)
    case getEmailAndPhone(organizationName : String,email : String)
    case verifyCode(appName : String,organizationName : String,email : String, code : String)
    case setPassword(organizationName : String, email : String, pwd : String, code : String)
    case signUp(appName : String,code : String, organizationName : String, email: String, name : String, pwd : String,config : CasdoorConfig, codeVerifier : String)
    case continueSignUp(config : CasdoorConfig, codeVerifier : String)
    
    var urlString : String{
        switch self {
        case .verficationCode:
            return "send-verification-code"
        case .getEmailAndPhone:
            return "get-email-and-phone"
        case .verifyCode:
            return "verify-code"
        case .setPassword:
            return "set-password"
        case .signUp:
            return "signup"
        case .continueSignUp:
            return "login"
        }
    }
    
    var httpMethod : HTTPMethod{
        switch self {
        case .verficationCode ,.verifyCode, .setPassword,.signUp,.continueSignUp:
            return .post
        case .getEmailAndPhone:
            return .get
        }
    }
    
    var isMultiPart : Bool{
        switch self {
        case .verficationCode,.setPassword:
            return true
        default :
            return false
        }
    }
    
    var body : [String : String]?{
        switch self {
        case let .verficationCode(appName, dest, method, type):
            [
                "captchaType"   : "none",
                "captchaToken"  : "undefined",
                "clientSecret"  : "undefined",
                "method"        : method,
//                "countryCode"   : "",
                "dest"          : dest,
                "type"          : type,
                "applicationId" : "admin/\(appName)",
//                "checkUser"     : dest
            ]
        case .getEmailAndPhone:
            nil
        case let .verifyCode(appName, organizationName, email, code):
            [
                "application"   : appName,
                "organization"  : organizationName,
                "username"      : email,
                "name"          : email,
                "code"          : code,
                "type"          : "login"
            ]
        case let .setPassword(organizationName,email,pwd, code):
            [
                "userOwner"     : organizationName,
                "userName"      : email,
                "oldPassword"   : pwd,
                "newPassword"   : pwd,
                "code"          : code
            ]
        case let .signUp(appName, code, organizationName, email, name, pwd ,_,_):
            [
                "emailCode"     : code,
                "organization"  : organizationName,
                "application"   : appName,
                "email"         : email,
                "name"          : name,
                "password"      : pwd
            ]
        case .continueSignUp(let config,_):
            [
                "application"   : config.appName,
                "type"          : "code"
            ]
        }
    }
    
    var queryParameters : [String : String]?{
        switch self {
        case .getEmailAndPhone(let organizationName, let email):
            return [
                "organization" : organizationName,
                "username" : email
            ]
        case .signUp( _,_, _, _, _, _,let config,let codeVerifier),.continueSignUp(let config, let codeVerifier):
            return [
                "clientId" : config.clientID,
                "responseType" : "code",
                "redirectUri" : config.redirectUri,
                "scope" : "profile",
                "code_challenge_method" : "S256",
                "code_challenge" : Utils.generateCodeChallenge(codeVerifier)
            ]
         default:
            return nil
        }
    }
    
    var header : [String : String]?{
        switch self {
        case .getEmailAndPhone, .verifyCode:
            return [
                "accept" : "application/json",
                "Content-Type" : "application/json"
            ]
        default:
            return nil
        }
    }
    
    func getRequest(endPoint : String, cookieHandler : CustomCookieHandler) -> URLRequest?{
        
        var urlComponents = URLComponents(string: endPoint + urlString)
        
        if let form = self.queryParameters{
            urlComponents?.queryItems = form.map { URLQueryItem(name: $0.key, value: $0.value) }
        }
        
        guard let url = urlComponents?.url else {
            print("Invalid URL")
            return nil
        }
        
        var request = URLRequest(url: url)
        request.method = self.httpMethod
        
        if let headers = self.header{
            for h in headers{
                request.setValue(h.value, forHTTPHeaderField: h.key)
            }
        }
        
        if let bodyComponents = self.body{
            if self.isMultiPart{
                let boundary = generateBoundary()
                request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
                request.httpBody = createBody(with: bodyComponents, boundary: boundary)
            }else{
                request.httpBody = try? JSONSerialization.data(withJSONObject: bodyComponents, options: [])
            }
        }
        print("body response", self.body)
        cookieHandler.applyCookies(for: &request)
        return request
    }
    
    // Helper function to create boundary string
    private func generateBoundary() -> String {
        return "Boundary-\(UUID().uuidString)"
    }

    // Helper function to create body data
    private func createBody(with parameters: [String: String]?, boundary: String) -> Data {
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
