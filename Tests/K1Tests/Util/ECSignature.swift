//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-19.
//

import Foundation
import K1

public protocol ECSignature {}
extension ECDSASignatureNonRecoverable: ECSignature {}
extension ECDSASignatureRecoverable: ECSignature {}
