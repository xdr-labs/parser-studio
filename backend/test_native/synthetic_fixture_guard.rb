# Shared offline native test guard. Before any class_eval of generated Ruby,
# read exact bytes from a fixed local fixture path and verify them against
# the import/recompile evidence emitted earlier by the reviewed Node compiler.
# This is a tamper-evidence gate, NOT a sandbox for arbitrary uploaded Ruby.
require 'json'
require 'digest'
require 'open3'

module SyntheticFixtureGuard
  class BoundaryError < StandardError; end
  extend self

  PROFILES = %w[sample_firewall sample_kv sample_extended sample_csv sample_syslog sample_syslog_cef sample_syslog_leef sample_cef sample_leef sample_enriched].freeze
  FILE_NAMES = PROFILES.flat_map { |s| ["customized_#{s}", "customized_#{s}.conf"] }.freeze
  FIXTURES = File.expand_path('../.tmp/native-fixtures', __dir__).freeze
  EVIDENCE = File.expand_path('../.tmp/synthetic-import-report.json', __dir__).freeze
  MAX_SOURCE = 128 * 1024

  def refuse(reason)
    raise BoundaryError, "Synthetic fixture boundary: #{reason}"
  end

  def verify_root!
    root_parent = File.dirname(FIXTURES)
    [root_parent, FIXTURES].each do |dir|
      refuse('directory is not trusted') unless File.lstat(dir).directory? &&
        !File.lstat(dir).symlink? && File.realpath(dir) == dir
    end
  rescue Errno::ENOENT, Errno::ELOOP
    refuse('generated directory is missing or redirected')
  end

  def read_regular(path, limit:)
    file = File.open(path, File::RDONLY | File::NOFOLLOW)
    begin
      stat = file.stat
      refuse('source is not an exclusive regular file') unless
        stat.file? && stat.nlink == 1 && stat.size <= limit
      file.read
    ensure
      file.close
    end
  rescue Errno::ENOENT, Errno::ELOOP, Errno::EISDIR, Errno::EACCES
    refuse('generated file is missing or unsafe')
  end

  def expected_hashes
    return @expected_hashes if @expected_hashes
    verify_root!
    parent = File.dirname(EVIDENCE)
    refuse('evidence directory is not trusted') unless File.realpath(parent) == parent
    data = JSON.parse(read_regular(EVIDENCE, limit: 16384))
    refuse('evidence origin/shape is unsupported') unless data['kind'] ==
      'xdr-labs.parser-studio.synthetic-pair-import.v0.1' &&
      data['origin'] == 'synthetic-repository-fixtures' &&
      data['verifiedExactPairs'] == PROFILES.size &&
      data['rejectedModifiedPairs'] == PROFILES.size &&
      data['targetImportVerified'] == false
    head, status = Open3.capture2('git', 'rev-parse', 'HEAD')
    refuse('cannot establish HEAD provenance') unless status.success? &&
      data['backendHead'] == head.strip
    hashes = data['originalHashes']
    refuse('source manifest does not cover exactly ten generated parser pairs') unless
      hashes.is_a?(Hash) && hashes.keys.sort == FILE_NAMES.sort &&
      hashes.values.all? { |h| h.is_a?(String) && h.match?(/\A[0-9a-f]{64}\z/) }
    @expected_hashes = hashes.freeze
  rescue JSON::ParserError
    refuse('source evidence is not valid JSON')
  end

  def verify_source!(path, bytes)
    verify_root!
    filename = File.basename(path)
    refuse('unreviewed synthetic filename') unless FILE_NAMES.include?(filename)
    refuse('source path is outside generated fixtures') unless
      File.expand_path(path) == File.join(FIXTURES, filename)
    refuse('source exceeds configured bound') unless
      bytes.is_a?(String) && bytes.bytesize <= MAX_SOURCE
    refuse('source SHA-256 does not match the reviewed generated pair') unless
      Digest::SHA256.hexdigest(bytes) == expected_hashes.fetch(filename)
    true
  end

  def read_source(path)
    filename = File.basename(path)
    refuse('unreviewed synthetic filename') unless FILE_NAMES.include?(filename)
    refuse('source path is outside generated fixtures') unless
      File.expand_path(path) == File.join(FIXTURES, filename)
    verify_root!
    bytes = read_regular(path, limit: MAX_SOURCE)
    verify_source!(path, bytes)
    bytes
  end
end
