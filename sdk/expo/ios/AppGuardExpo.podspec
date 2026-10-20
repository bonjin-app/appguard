require 'json'
package = JSON.parse(File.read(File.join(__dir__, '..', 'package.json')))
Pod::Spec.new do |s|
  s.name = 'AppGuardExpo'
  s.version = package['version'].split('-').first
  s.summary = package['description']
  s.description = package['description']
  s.license = { :type => 'Apache-2.0', :file => '../LICENSE' }
  s.author = package['author']
  s.homepage = package['homepage']
  s.platforms = { :ios => '16.4' }
  s.swift_version = '5.9'
  s.source = { :git => package['homepage'] }
  s.static_framework = true
  s.dependency 'ExpoModulesCore'
  s.dependency 'AppGuardApple', package['version'].split('-').first
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
  s.source_files = 'AppGuardModule.swift'
end
