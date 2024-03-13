#!/usr/bin/env ruby

require 'erb'
require 'octokit'

GITHUB_REPO = 'sifraitech/grandine'
GRANDINE_GITHUB_ACCESS_TOKEN = ENV['GRANDINE_GITHUB_ACCESS_TOKEN']

BUILD_DIR = File.join(__dir__, '..', '..', 'target')
RELEASE_NOTES_FILE = File.join(__dir__, 'release_notes.md.erb')

ASSETS = [
  {
    asset_name: 'grandine-%s-linux-aarch64',
    file_path: File.join(BUILD_DIR, 'aarch64-unknown-linux-gnu', 'compact', 'grandine'),
  },
  {
    asset_name: 'grandine-%s-linux-amd64',
    file_path: File.join(BUILD_DIR, 'x86_64-unknown-linux-gnu', 'compact', 'grandine'),
    executable_for_version: true,
  },
]

def load_release_notes(file_path, tag)
  ERB.new(File.read(file_path)).result(binding)
end

def grandine_version
  executable = ASSETS.find { |asset| asset[:executable_for_version] }
  executable_file_path = executable.to_h[:file_path].to_s

  if executable_file_path.empty?
    raise 'cannot get Grandine version because executable asset is not set'
  end

  /\AGrandine (?<version>.+)\Z/ =~ `#{executable_file_path} --version`

  if version.empty?
    raise 'failed to parse version from Grandine executable'
  end

  version
end

if GRANDINE_GITHUB_ACCESS_TOKEN.to_s.empty?
  raise 'please set the GRANDINE_GITHUB_ACCESS_TOKEN environment variable'
end

client = Octokit::Client.new(access_token: GRANDINE_GITHUB_ACCESS_TOKEN)
tag = "#{grandine_version}"
release_notes = load_release_notes(RELEASE_NOTES_FILE, tag)

puts "creating GitHub release #{tag}"
p response = client.create_release(GITHUB_REPO, tag, name: tag, body: release_notes, prerelease: true)

ASSETS.each do |asset|
  name = format(asset[:asset_name], tag)

  puts "uploading #{name} to #{response[:url]}"

  p client.upload_asset(
    response[:url],
    asset[:file_path],
    name: name,
    content_type: 'application/octet-stream',
  )
end
