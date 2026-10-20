require 'json'
package = JSON.parse(File.read(File.join(__dir__, 'package.json')))
Pod::Spec.new do |s|
  s.name = 'AppGuardApple'
  s.version = package['version'].split('-').first
  s.summary = 'AppGuard native request signing and enrollment possession proof'
  s.description = s.summary
  s.license = { :type => 'Apache-2.0', :file => 'vendor/apple/LICENSE' }
  s.author = package['author']
  s.homepage = package['homepage']
  s.platforms = { :ios => '16.4' }
  s.swift_version = '5.9'
  s.source = { :git => package['homepage'] }
  s.static_framework = true
  s.frameworks = 'Security', 'CryptoKit', 'DeviceCheck'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
  s.source_files = 'vendor/apple/Sources/AppGuardApple/*.swift'
  s.resource_bundles = { 'AppGuardApplePrivacy' => ['vendor/apple/Sources/AppGuardApple/Resources/PrivacyInfo.xcprivacy'] }
end
