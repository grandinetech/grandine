#!/usr/bin/env ruby

# This script tracks coverage at test case granularity.
# If a glob in the codebase matches the path of a test case directory,
# every file in that test case is assumed to be covered.

SUBMODULE = 'consensus-spec-tests'

IGNORED_GLOBS = %w[
  **/README.md
  .git*
  LICENSE
  configs/*.yaml
  presets/*/*.yaml
  presets/*/trusted_setups/*.json
  tests/*/*/light_client/sync/pyspec_tests/*/*.{ssz_snappy,yaml}
  tests/*/*/light_client/update_ranking/pyspec_tests/*/*.{ssz_snappy,yaml}
  tests/*/*/light_client/data_collection/pyspec_tests/*/*.{ssz_snappy,yaml}
  tests/*/eip6110/*/*/*/*/*.{ssz_snappy,yaml}
  tests/*/fulu/*/*/*/*/*.{ssz_snappy,yaml}
  tests/*/whisk/*/*/*/*/*.{ssz_snappy,yaml}
  tests/diagnostics_obj.json{,.lock}
].map! { |glob| File.join(SUBMODULE, glob) }

GIT_LS_FILES_COMMAND = %W[
  git
  -C #{SUBMODULE}
  ls-files
  -z
]

GIT_GREP_COMMAND = %W[
  git
  grep
  --extended-regexp
  -h
  --no-color
  --no-column
  --no-line-number
  --only-matching
  --untracked
  #{SUBMODULE}/tests/[^"`]+
]

Dir.chdir(File.join(__dir__, '..', '..'))

all_files = IO.popen(GIT_LS_FILES_COMMAND, IO::RDONLY | IO::BINARY) do |io|
  io.each_line("\0").map do |line|
    File.join(SUBMODULE, line.chomp!("\0"))
  end
end

covered_globs = IO.popen(GIT_GREP_COMMAND) do |io|
  io.each_line.map do |line|
    File.join(line.chomp!, '*.{ssz_snappy,yaml}')
  end
end

covered_files = Dir.glob(covered_globs + IGNORED_GLOBS)
uncovered_files = all_files - covered_files

if uncovered_files.empty?
  puts("All #{all_files.size} files in #{SUBMODULE} are covered by tests.")
else
  heading = <<~END
    #{uncovered_files.size} of #{all_files.size} \
    files in #{SUBMODULE} are not covered by tests:
  END

  puts(heading, uncovered_files)

  exit(false)
end
