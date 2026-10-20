# Run against a relocated package using the consumer's CocoaPods runtime.
require 'cocoapods'
root = Pathname(ARGV.fetch(0, File.expand_path('..', __dir__))).realpath
file = root.join('ios/appguard_flutter.podspec')
spec = Pod::Specification.from_file(file)
accessor = Pod::Sandbox::FileAccessor.new(file.dirname, spec.consumer(:ios))
sources = Dir.glob(root.join('ios/Classes/**/*.swift').to_s).map { |p| Pathname(p).realpath }.sort
abort 'APPGUARD_POD_SOURCE_MISMATCH' unless !sources.empty? && accessor.source_files.map(&:realpath).sort == sources
manifest = root.join('ios/Classes/Native/Resources/PrivacyInfo.xcprivacy').realpath
bundles = accessor.resource_bundles.transform_values { |paths| paths.map(&:realpath).sort }
abort 'APPGUARD_PRIVACY_RESOURCE_MISMATCH' unless bundles == { 'AppGuardFlutterPrivacy' => [manifest] }
expected = { 'NSPrivacyAccessedAPITypes' => [{
  'NSPrivacyAccessedAPIType' => 'NSPrivacyAccessedAPICategoryFileTimestamp',
  'NSPrivacyAccessedAPITypeReasons' => ['C617.1']
}] }
abort 'APPGUARD_PRIVACY_REASON_MISMATCH' unless Xcodeproj::Plist.read_from_path(manifest) == expected
puts "#{sources.size} actual CocoaPods Swift sources; required-reason privacy resource bundle resolved"
