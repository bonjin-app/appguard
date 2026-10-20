# Run with the Ruby/CocoaPods runtime used by your native consumer.
require 'cocoapods'
require 'json'
root = Pathname(ARGV.fetch(0, File.expand_path('..', __dir__))).realpath
expected = {
  'AppGuardApple' => Dir.glob(root.join('vendor/apple/Sources/AppGuardApple/*.swift').to_s).map { |p| Pathname(p).realpath }.sort,
  'AppGuardExpo' => [root.join('ios/AppGuardModule.swift').realpath]
}
abort 'APPGUARD_NO_STAGED_SWIFT' if expected['AppGuardApple'].empty?
['AppGuardApple.podspec', 'ios/AppGuardExpo.podspec'].each do |relative|
  file = root.join(relative)
  spec = Pod::Specification.from_file(file)
  abort 'APPGUARD_POD_VERSION' unless Pod::Requirement.new('>= 0').satisfied_by?(spec.version)
  accessor = Pod::Sandbox::FileAccessor.new(file.dirname, spec.consumer(:ios))
  actual = accessor.source_files.map(&:realpath).sort
  abort "APPGUARD_POD_SOURCE_MISMATCH: #{spec.name}" unless actual == expected.fetch(spec.name)
  abort 'APPGUARD_POD_SOURCE_ESCAPE' unless actual.all? { |p| p.to_s.start_with?(root.to_s + '/') }
  if spec.name == 'AppGuardApple'
    manifest = root.join('vendor/apple/Sources/AppGuardApple/Resources/PrivacyInfo.xcprivacy').realpath
    bundles = accessor.resource_bundles.transform_values { |paths| paths.map(&:realpath).sort }
    abort 'APPGUARD_PRIVACY_RESOURCE_MISMATCH' unless bundles == { 'AppGuardApplePrivacy' => [manifest] }
    privacy = Xcodeproj::Plist.read_from_path(manifest)
    expected_privacy = { 'NSPrivacyAccessedAPITypes' => [{
      'NSPrivacyAccessedAPIType' => 'NSPrivacyAccessedAPICategoryFileTimestamp',
      'NSPrivacyAccessedAPITypeReasons' => ['C617.1']
    }] }
    abort 'APPGUARD_PRIVACY_REASON_MISMATCH' unless privacy == expected_privacy
    puts 'AppGuardApplePrivacy: actual CocoaPods resource bundle resolves the required-reason manifest'
  end
  license_file = spec.license[:file] || spec.license['file']
  license = file.dirname.join(license_file).realpath
  abort 'APPGUARD_POD_LICENSE_ESCAPE' unless license.to_s.start_with?(root.to_s + '/')
  puts "#{spec.name}: #{actual.size} actual CocoaPods Swift sources; local license and version valid"
end
