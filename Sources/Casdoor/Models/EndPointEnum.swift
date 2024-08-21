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
    case getEmailAndPhone(endpoint : String,email : String)
    case verifyCode
    
    var urlString : String{
        switch self {
        case .verficationCode(let endPoint,_):
            return "\(endPoint)send-verification-code"
        case .getEmailAndPhone(let endPoint,_):
            return "\(endPoint)get-email-and-phone"
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
    
    var body : [String : String]{
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
        case .getEmailAndPhone(_, _):
            [:]
        case .verifyCode:
            [
                "application":"krispcall",
                "organization":"krispcall",
                "username":"sandeep.tharu@krispcallmail.com",
                "name":"sandeep.tharu@krispcallmail.com",
                "code":"123456",
                "type":"login"
            ]
        }
    }
    
    func getRequest(endPoint : String) -> URLRequest?{
        guard let url = URL(string: endPoint + urlString) else {
            print("Invalid URL")
            return nil
        }
        var request = URLRequest(url: url)
        request.method = self.httpMethod
        
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
