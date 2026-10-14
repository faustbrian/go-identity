# frozen_string_literal: true

require "json"
require "minitest/autorun"
require "open3"
require "rbconfig"
require "tmpdir"

class GenerateHTTPCatalogTest < Minitest::Test
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
