import Foundation
import Cblake2

public struct Blake2bHasher {
	/// Hash data and return the results with a single function call.
	public static func hash<C>(_ bytes:C, outputLength length:size_t) throws -> Data where C:Collection, C.Element == UInt8 {
		var newHasher = try Blake2bHasher(outputLength:length)
		try newHasher.update(bytes:bytes)
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
	
	public let outputLength:size_t

	/// Initialize a new blake2b hasher
	public init(outputLength:size_t) throws {
		try Self.validateOutputLength(outputLength)
		guard blake2b_init(&state, outputLength) == 0 else {
			throw Blake2bError.initializationError
		}
		self.outputLength = outputLength
	}
		
	/// Update the hasher with new data
	public mutating func update<C>(bytes input:C) throws where C:Collection, C.Element == UInt8 {
		if input.count > 0 {
			if let getThing = try input.withContiguousStorageIfAvailable({ someBytes in
				let baseaddr = UnsafeRawPointer(someBytes.baseAddress!)
				guard blake2b_update(&state, baseaddr, input.count) == 0 else {
					throw Blake2bError.updateError
				}
			}) {
				return getThing
			} else {
				let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: input.count)
				defer { buffer.deallocate() }
				_ = buffer.initialize(from: input)
				guard blake2b_update(&state, UnsafeRawPointer(buffer.baseAddress!), input.count) == 0 else {
					throw Blake2bError.updateError
				}
			}
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
