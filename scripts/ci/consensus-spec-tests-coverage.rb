#!/usr/bin/env ruby

# This script tracks coverage at test case granularity.
# If a glob in the codebase matches the path of a test case directory,
# every file in that test case is assumed to be covered.

CONSENSUS_SPEC_TESTS = 'consensus-spec-tests'

CONSENSUS_IGNORED_GLOBS = %w[
  .version
  **/*.md
  **/*.py
  **/*.typed
  tests/generators/**/*
  tests/*/*/fork_choice_compliance/*/*/*/*.{ssz_snappy,yaml}
  tests/*/*/light_client/single_merkle_proof/*/*/*.{ssz_snappy,yaml}
  tests/*/*/light_client/sync/pyspec_tests/*/*.{ssz_snappy,yaml}
  tests/*/*/light_client/update_ranking/pyspec_tests/*/*.{ssz_snappy,yaml}
  tests/*/*/light_client/data_collection/pyspec_tests/*/*.{ssz_snappy,yaml}
  tests/*/*/ssz_static/PartialDataColumnGroupID/*/*/*.{ssz_snappy,yaml}
  tests/*/*/ssz_static/PartialDataColumnHeader/*/*/*.{ssz_snappy,yaml}
  tests/*/*/ssz_static/PartialDataColumnPartsMetadata/*/*/*.{ssz_snappy,yaml}
  tests/*/*/ssz_static/PartialDataColumnSidecar/*/*/*.{ssz_snappy,yaml}
  tests/*/heze/*/*/*/*/*.{ssz_snappy,yaml}
  tests/*/*/fast_confirmation/*/*/*/*.{ssz_snappy,yaml}
  tests/*/*/networking/*/pyspec_tests/*/*.{ssz_snappy,yaml}
].map! { |glob| File.join(CONSENSUS_SPEC_TESTS, glob) }

SSZ_SPEC_TESTS = 'ssz-spec-tests'

SSZ_IGNORED_GLOBS = %w[
  .version
].map! { |glob| File.join(SSZ_SPEC_TESTS, glob) }

Dir.chdir(File.join(__dir__, '..', '..'))

success = true

# check consensus spec coverage

all_files = IO.popen(['find', CONSENSUS_SPEC_TESTS, '-type', 'f', '-print0'], IO::RDONLY | IO::BINARY) do |io|
  io.each_line("\0").map { |line| line.delete_suffix("\0") }
end

covered_globs = IO.popen(%W[grep -ErohI #{CONSENSUS_SPEC_TESTS}/tests/[^\"`]+]) do |io|
  io.each_line.map do |line|
    File.join(line.chomp!, '*.{ssz_snappy,yaml}')
  end
end

covered_files = Dir.glob(covered_globs + CONSENSUS_IGNORED_GLOBS)
uncovered_files = all_files - covered_files

if uncovered_files.empty?
  puts("All #{all_files.size} files in #{CONSENSUS_SPEC_TESTS} are covered by tests.")
else
  heading = <<~END
    #{uncovered_files.size} of #{all_files.size} \
    files in #{CONSENSUS_SPEC_TESTS} are not covered by tests:
  END

  puts(heading, uncovered_files)

  success = false
end

# check ssz spec coverage

all_files = IO.popen(['find', SSZ_SPEC_TESTS, '-type', 'f', '-print0'], IO::RDONLY | IO::BINARY) do |io|
  io.each_line("\0").map { |line| line.delete_suffix("\0") }
end

covered_globs = IO.popen(%W[grep -ErohI #{SSZ_SPEC_TESTS}/fixtures/[^\"`]+\\.json]) do |io|
  io.each_line.map { |line| line.chomp }
end

covered_files = Dir.glob(covered_globs + SSZ_IGNORED_GLOBS)
uncovered_files = all_files - covered_files

if uncovered_files.empty?
  puts("All #{all_files.size} files in #{SSZ_SPEC_TESTS} are covered by tests.")
else
  heading = <<~END
    #{uncovered_files.size} of #{all_files.size} \
    files in #{SSZ_SPEC_TESTS} are not covered by tests:
  END

  puts(heading, uncovered_files)

  success = false
end

exit(success)
