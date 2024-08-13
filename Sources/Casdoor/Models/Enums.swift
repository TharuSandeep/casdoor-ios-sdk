//
//  File.swift
//  
//
//  Created by Sandeep Tharu on 12/08/2024.
//

import Foundation
import AF

//public enum MfaType : String{
//    case email, app, sms
//}

public enum AuthType : String{
    case mfa = "NextMfa"
    case socialLogin = "SocialLogin"
    case login = "Login"
}
