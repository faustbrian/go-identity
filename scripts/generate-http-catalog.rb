#!/usr/bin/env ruby
# frozen_string_literal: true

# Rebuild the owned canonical-operation input, not an implementation report.
require "json"
require "digest"

abort "usage: generate-http-catalog.rb API_OPERATIONS.md OPERATION_SEMANTICS.json PUBLIC_CONTRACTS.json OUTPUT [NATIVE_CONTRACTS.json]" unless (4..5).cover?(ARGV.length)
api, semantics, contracts, output, native_source = ARGV
rows = JSON.parse(File.read(semantics)).fetch("operations")
public_contracts = JSON.parse(File.read(contracts))
typed = public_contracts.fetch("operations").to_h { |row| [row.fetch("id"), row] }
types = public_contracts.fetch("types").to_h { |row| [row.fetch("id"), row.fetch("definition")] }
if native_source
  native = JSON.parse(File.read(native_source))
  native_rows = native.fetch("semantics")
  native_typed = native.fetch("operations").to_h { |row| [row.fetch("id"), row] }
  native_types = native.fetch("types").to_h { |row| [row.fetch("id"), row.fetch("definition")] }
  abort "native contract collision" unless (rows.map { |row| row.fetch("id") } & native_rows.map { |row| row.fetch("id") }).empty? && (typed.keys & native_typed.keys).empty? && (types.keys & native_types.keys).empty?
  rows += native_rows
  typed.merge!(native_typed)
  types.merge!(native_types)
end
canonical = lambda do |value|
  case value
  when Hash then value.keys.sort.to_h { |key| [key, canonical.call(value.fetch(key))] }
  when Array then value.map { |item| canonical.call(item) }
  else value
  end
end
# Identity uses sorted compact JSON plus LF. Pretty-printer versions disagree
# on empty collections, so presentation bytes must not define contract identity.
digest = ->(value) { Digest::SHA256.hexdigest(JSON.generate(canonical.call(value)) + "\n") }
abort "operation inventories differ" unless rows.map { |r| r.fetch("id") }.sort == typed.keys.sort
operations = rows.sort_by { |r| r.fetch("id") }.map do |row|
  contract = typed.fetch(row.fetch("id"))
  abort "transport drift" unless row.slice("exposure", "http_method", "http_path", "openapi_operation_id") == contract.fetch("transport")
  request, result, error = contract.fetch("request_type"), contract.fetch("result_type"), contract.fetch("error_types").fetch(0)
  row.merge("request_schema" => request, "result_schema" => result, "error_schema" => error,
    "request_digest" => digest.call(types.fetch(request)), "result_digest" => digest.call(types.fetch(result)), "error_digest" => digest.call(types.fetch(error)))
end
result = {
  "schema_version" => 1,
  "provenance" => {
    "authority" => "API_OPERATIONS.md",
    "operation_inventory_sha256" => Digest::SHA256.file(api).hexdigest,
    "semantics_sha256" => Digest::SHA256.file(semantics).hexdigest,
    "operation_contracts_sha256" => digest.call(operations)
  },
  "operations" => operations
}
result.fetch("provenance")["native_contracts_sha256"] = Digest::SHA256.file(native_source).hexdigest if native_source
File.write(output, JSON.generate(canonical.call(result)) + "\n")
puts "HTTP catalog: #{operations.length} canonical rows; no handler-completion claim"
