import Foundation
import Cblake2

public struct Blake2bHasher {
    public static func hash(data:Data, length:size_t) throws -> Data {
        var newHasher = try Blake2bHasher(outputLength:length)
        try newHasher.update(data:data)
        return try newHasher.export()
    }
    
    fileprivate static func validateOutputLength(_ olen:size_t) throws {
    	guard olen > 0 && olen <= 64 else {
    		throw Blake2bError.invalidOutputLength
    	}
    }
    
    public enum Blake2bError:Swift.Error {
    	case invalidOutputLength
        case initializationError
        case updateError
        case exportError
    }

    fileprivate var state = blake2b_state()
    
    let outputLength:size_t

    /// Initialize a new blake2s hasher
    public init(outputLength:size_t) throws {
    	try Self.validateOutputLength(outputLength)
        guard blake2b_init(&state, outputLength) == 0 else {
            throw Blake2bError.initializationError
        }
        self.outputLength = outputLength
    }
    
    public mutating func update(data input:Data) throws {
        try input.withUnsafeBytes { unsafeBuffer in
            try self.update(unsafeBuffer)
        }
    }
    
    /// Update the hasher with new data
    public mutating func update(_ input:UnsafeRawBufferPointer) throws {
        guard blake2b_update(&state, UnsafeRawPointer(input.baseAddress!), input.count) == 0 else {
            throw Blake2bError.updateError
        }
    }

    /// Finish the hashing
    public mutating func export() throws -> Data {
        let finalHash = UnsafeMutableBufferPointer<UInt8>.allocate(capacity:outputLength)
        defer {
            finalHash.deallocate()
        }
        guard blake2b_final(&state, finalHash.baseAddress!, outputLength) == 0 else {
            throw Blake2bError.updateError
        }
        return Data(buffer:finalHash)
    }
    
    mutating func reset() throws {
        guard blake2b_init(&state, outputLength) == 0 else {
            throw Blake2bError.updateError
        }
    }
}
