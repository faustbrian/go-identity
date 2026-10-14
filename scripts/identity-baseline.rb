#!/usr/bin/env ruby
# Development consumer runner: immutable supplier archives, temporary Go wiring,
# one command, then cleanup. It does not modify suppliers or qualify a release.
require "json"
require "tmpdir"
require "fileutils"
require "open3"
require "find"

def remove_scratch(path)
  # Go's module cache makes directories read-only. Walk without following
  # symlinks and chmod only directories in this invocation's owned scratch.
  Find.find(path) do |entry|
    info = File.lstat(entry)
    raise "scratch ownership changed" unless info.uid == Process.uid
    File.chmod(info.mode | 0700, entry) if info.directory?
  end
  FileUtils.remove_entry_secure(path)
end

def run_child(env, args, directory)
  pid = Process.spawn(env, *args, chdir: directory, pgroup: true)
  handlers = {}
  %w[INT TERM].each do |signal|
    handlers[signal] = Signal.trap(signal) do
      begin
        Process.kill(signal, -pid)
      rescue Errno::ESRCH
      end
    end
  end
  _, status = Process.wait2(pid)
  raise "baseline command failed" unless status.success?
ensure
  handlers&.each { |signal, handler| Signal.trap(signal, handler) }
end

def go_module(directory)
  declaration = File.foreach(File.join(directory, "go.mod")).find { |line| line.start_with?("module ") }
  raise "supplier module declaration missing" unless declaration
  declaration.delete_prefix("module ").strip
end

scratch = nil
begin
  collection = ARGV.shift
  raise "usage: ruby scripts/identity-baseline.rb COLLECTION COMMAND [FLAGS]" unless collection && !ARGV.empty?
  root = File.expand_path("..", __dir__)
  raise "source collection unavailable" unless File.directory?(collection)
  version, status = Open3.capture2("go", "env", "GOVERSION")
  raise "Go 1.27.2 required" unless status.success? && version.strip == "go1.27.2"
  scratch = Dir.mktmpdir("identity-baseline-")
  env = {"GOCACHE" => File.join(scratch, "build"), "GOMODCACHE" => File.join(scratch, "modules"), "GOTMPDIR" => File.join(scratch, "tmp"), "GOWORK" => File.join(scratch, "go.work")}
  %w[build modules tmp suppliers].each { |name| Dir.mkdir(File.join(scratch, name), 0700) }
  uses = []
  replacements = {}
  identity_paths = {}
  module_inputs = []
  JSON.parse(File.read(File.join(root, "modules.json"))).fetch("modules").each do |entry|
    directory = File.expand_path(entry.fetch("directory"), root)
    raise "identity module escaped its repository" unless directory == root || directory.start_with?(root + File::SEPARATOR)
    uses << directory
    identity_paths[go_module(directory)] = directory
    module_inputs << File.join(directory, "go.mod")
  end
  sources = JSON.parse(File.read(File.join(root, "reference", "LOCAL_SOURCES.json"))).fetch("sources")
  sources.each_with_index do |source, index|
    revision = source.fetch("revision")
    repository = source.fetch("repository")
    raise "invalid supplier identity" unless revision.match?(/\A[0-9a-f]{40}\z/) && repository.match?(/\Ago-[a-z0-9-]+\z/)
    supplier = File.expand_path(repository, collection)
    exact, status = Open3.capture2("git", "-C", supplier, "rev-parse", "#{revision}^{commit}")
    raise "committed supplier unavailable: #{repository}" unless status.success? && exact.strip == revision
    target = File.join(scratch, "suppliers", index.to_s)
    Dir.mkdir(target, 0700)
    archive = File.join(scratch, "suppliers", "#{index}.tar")
    # Finish the producer before extraction; BSD tar may close a stream after
    # its end markers while git is still writing padding, producing SIGPIPE.
    raise "supplier archive failed: #{repository}" unless system("git", "-C", supplier, "archive", "-o", archive, revision)
    raise "supplier extraction failed: #{repository}" unless system("tar", "-xf", archive, "-C", target)
    File.unlink(archive)
    source.fetch("modules").each do |relative|
      directory = File.expand_path(relative, target)
      raise "supplier module escaped its archive" unless directory == target || directory.start_with?(target + File::SEPARATOR)
      path = go_module(directory)
      raise "duplicate supplier module" if replacements.key?(path)
      replacements[path] = directory
      module_inputs << File.join(directory, "go.mod")
    end
  end
  quote = ->(value) { JSON.generate(value) }
  workspace = "go 1.27.0\n\nuse (\n" + uses.map { |directory| "\t#{quote.call(directory)}\n" }.join + ")\n\nreplace (\n"
  workspace += replacements.map { |path, directory| "\t#{path} => #{quote.call(directory)}\n" }.join
  # A workspace module cannot have an all-version replacement. Bind only its
  # actually recorded requirements, including unavailable historical refs.
  identity_versions = {}
  module_inputs.each do |path|
    File.foreach(path) do |line|
      required = line.match(/^\s*(?:require\s+)?(github\.com\/faustbrian\/go-identity(?:\/\S+)?)\s+(v\S+)/)
      next unless required && identity_paths.key?(required[1])
      identity_versions[[required[1], required[2]]] = identity_paths.fetch(required[1])
    end
  end
  workspace += identity_versions.map { |(path, version), directory| "\t#{path} #{version} => #{quote.call(directory)}\n" }.join + ")\n"
  File.write(env.fetch("GOWORK"), workspace, mode: "wx", perm: 0600)
  if ARGV == ["integration"]
    # This is only the frozen B1 native check, not another gate/receipt engine.
    # -p 1 also serializes cluster-scoped audit-role fixtures between packages.
    run_child(env, ["go", "test", "-p", "1", "-race", "-tags=integration", "-run", "^(TestReferencePostgresBaseline|TestBaseline|TestDurableCounter|TestFeatureInputAdmission)", "-count=1", "../risk/postgres", "../postgres", ".", "./cmd/identity-baseline"], File.join(root, "reference"))
  else
    binary = File.join(scratch, "identity-baseline")
    run_child(env, ["go", "build", "-o", binary, "./cmd/identity-baseline"], File.join(root, "reference"))
    run_child(env, [binary, *ARGV], root)
  end
rescue StandardError => error
  warn error.message
  exit 1
ensure
  remove_scratch(scratch) if scratch && File.directory?(scratch)
end
