#!/usr/bin/env ruby
# Consumer runner: the reference module's pinned public dependencies, private
# disposable Go caches and one command. This does not qualify a release.
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

scratch = nil
begin
  # Retain the original first argument for existing walkthrough commands.
  # It no longer selects source or requires any sibling checkout.
  legacy_collection = ARGV.shift
  raise "usage: ruby scripts/identity-baseline.rb COLLECTION COMMAND [FLAGS]" unless legacy_collection && !ARGV.empty?
  root = File.expand_path("..", __dir__)
  version, status = Open3.capture2("go", "env", "GOVERSION")
  raise "Go 1.27.2 required" unless status.success? && version.strip == "go1.27.2"
  scratch = Dir.mktmpdir("identity-baseline-")
  env = {"GOCACHE" => File.join(scratch, "build"), "GOMODCACHE" => File.join(scratch, "modules"), "GOTMPDIR" => File.join(scratch, "tmp"), "GOWORK" => "off"}
  %w[build modules tmp].each { |name| Dir.mkdir(File.join(scratch, name), 0700) }
  if ARGV == ["integration"]
    # This is only the frozen B1 native check, not another gate/receipt engine.
    # Each module uses its real public graph, not a cross-module workspace.
    %w[risk/postgres postgres reference].each do |owner|
      run_child(env, ["go", "test", "-p", "1", "-race", "-tags=integration", "-run", "^(TestReferencePostgresBaseline|TestBaseline|TestDurableCounter|TestFeatureInputAdmission)", "-count=1", "./..."], File.join(root, owner))
    end
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
