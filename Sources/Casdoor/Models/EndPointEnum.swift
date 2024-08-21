//
//  File.swift
//  
//
//  Created by Sandeep Tharu on 19/08/2024.
//

import Foundation
import AF

public enum Endpoint{
    
    case verficationCode(endpoint : String,email : String)
    case getEmailAndPhone(organizationName : String,email : String)
    case verifyCode(organizationName : String,email : String, code : String)
    
    enum BodyType{
        case formData
        case requestPayload
        case empty
    }
    
    var urlString : String{
        switch self {
        case .verficationCode:
            return "send-verification-code"
        case .getEmailAndPhone:
            return "get-email-and-phone"
        case .verifyCode:
            return "verify-code"
        }
    }
    
    var httpMethod : HTTPMethod{
        switch self {
        case .verficationCode ,.verifyCode:
            return .post
        case .getEmailAndPhone:
            return .get
        }
    }
    
    var isMultiPart : Bool{
        switch self {
        case .verficationCode:
            return true
        default :
            return false
        }
    }
    
    var body : [String : String]?{
        switch self {
        case .verficationCode(_ , let email):
            [
                "captchaType"   : "none",
                "captchaToken"  : "undefined",
                "clientSecret"  : "undefined",
                "method"        : "forget",
                "countryCode"   : "",
                "dest"          : email,
                "type"          : "email",
                "applicationId" : "admin/krispcall",
                "checkUser"     : email
            ]
        case .getEmailAndPhone:
            nil
        case .verifyCode(let organizationName,let email, let code):
            [
                "application"   : organizationName,
                "organization"  : organizationName,
                "username"      : email,
                "name"          : email,
                "code"          : code,
                "type"          : "login"
            ]
        }
    }
    
    var queryParameters : [String : String]?{
        switch self {
        case .verficationCode:
            return nil
        case .getEmailAndPhone(let organizationName, let email):
            return [
                "organization" : organizationName,
                "username" : email
            ]
        case .verifyCode:
            return nil
        }
    }
    
    var header : [String : String]?{
        switch self {
        case .verficationCode:
            return nil
        case .getEmailAndPhone, .verifyCode:
            return [
                "accept" : "application/json",
                "Content-Type" : "application/json"
            ]
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
