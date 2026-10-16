# frozen_string_literal: true

require "json"
require "digest"
require "minitest/autorun"
require "open3"
require "rbconfig"
require "tmpdir"

class GenerateHTTPCatalogTest < Minitest::Test
  def test_native_operation_is_added_without_changing_existing_contracts
    Dir.mktmpdir("identity-http-native-test-") do |directory|
      api, semantics, contracts, output, native = %w[api semantics contracts output native].map { |name| File.join(directory, name) }
      row = lambda do |id|
        transport = {"exposure" => "both", "http_method" => "POST", "http_path" => "/#{id}", "openapi_operation_id" => id}
        schema = "schema:#{id}.v1"
        {"semantics" => [transport.merge("id" => id)],
         "operations" => [{"id" => id, "transport" => transport, "request_type" => schema, "result_type" => schema, "error_types" => [schema]}],
         "types" => [{"id" => schema, "definition" => {"fields" => [], "schema_id" => schema}}]}
      end
      existing, addition = row.call("existing"), row.call("native")
      File.write(api, "fixture authority\n")
      File.write(semantics, JSON.generate({"operations" => existing.fetch("semantics")}))
      File.write(contracts, JSON.generate(existing.slice("operations", "types")))
      File.write(native, JSON.generate(addition))
      command = [RbConfig.ruby, File.expand_path("generate-http-catalog.rb", __dir__), api, semantics, contracts, output]
      stdout, stderr, status = Open3.capture3(*command)
      assert status.success?, "baseline generation failed: #{stdout} #{stderr}"
      baseline = JSON.parse(File.binread(output))
      stdout, stderr, status = Open3.capture3(*command, native)
      assert status.success?, "native generation failed: #{stdout} #{stderr}"
      generated = JSON.parse(File.binread(output))
      assert_equal Digest::SHA256.file(api).hexdigest, generated.fetch("provenance").fetch("operation_inventory_sha256")
      assert_equal %w[existing native], generated.fetch("operations").map { |item| item.fetch("id") }
      assert_equal baseline.fetch("operations").first, generated.fetch("operations").first
      assert_equal Digest::SHA256.file(native).hexdigest, generated.fetch("provenance").fetch("native_contracts_sha256")
      before = File.binread(output)
      [existing, addition.merge("types" => existing.fetch("types"))].each do |collision|
        File.write(native, JSON.generate(collision))
        stdout, stderr, status = Open3.capture3(*command, native)
        refute status.success?, "colliding native authority was accepted: #{stdout}"
        assert_includes stderr, "native contract collision"
        assert_equal before, File.binread(output), "rejected source replaced the existing catalog"
      end
    end
  end

  def test_empty_collections_have_portable_content_identity
    Dir.mktmpdir("identity-http-catalog-test-") do |directory|
      paths = %w[api semantics contracts output].map { |name| File.join(directory, name) }
      transport = {"exposure" => "both", "http_method" => "GET", "http_path" => "/healthz", "openapi_operation_id" => "identity.health"}
      schema = "schema:identity.health.request.v1"
      # Deliberately unsorted keys: the content identity must not inherit
      # source insertion order or version-dependent empty-array formatting.
      definition = {"schema_id" => schema, "name" => "HealthRequest", "fields" => []}
      File.write(paths[0], "fixture authority\n")
      File.write(paths[1], JSON.generate({"operations" => [transport.merge("id" => "identity.health")]}))
      contracts = {
        "operations" => [{"id" => "identity.health", "transport" => transport, "request_type" => schema, "result_type" => schema, "error_types" => [schema]}],
        "types" => [{"id" => schema, "definition" => definition}]
      }
      File.write(paths[2], JSON.generate(contracts))
      stdout, stderr, status = Open3.capture3(RbConfig.ruby, File.expand_path("generate-http-catalog.rb", __dir__), *paths)
      assert status.success?, "generation failed: #{stdout} #{stderr}"
      bytes = File.binread(paths[3])
      generated = JSON.parse(bytes)
      # SHA-256 of the fixed sorted compact JSON literal plus LF, independently
      # calculated; old and new Ruby pretty printers disagree on this value.
      expected = "a8ffdf884e5c9ddaab0131a804219e668fe3cf8b5ebc2ee3045e0b8ef0ea5974"
      row = generated.fetch("operations").fetch(0)
      %w[request_digest result_digest error_digest].each { |key| assert_equal expected, row.fetch(key) }
      assert_equal JSON.generate(generated) + "\n", bytes
    end
  end
end
