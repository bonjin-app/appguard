Pod::Spec.new do |s|
  s.name = 'appguard_flutter'
  s.version = '0.0.0'
  s.summary = 'Experimental AppGuard native request bridge'
  s.description = 'Native request preparation and enrollment possession proof. No network transport.'
  s.homepage = 'https://github.com/uulab/appguard'
  s.license = { :type => 'Apache-2.0', :file => '../LICENSE' }
  s.author = 'UULab'
  s.source = { :path => '.' }
  s.source_files = 'Classes/**/*.swift'
  s.dependency 'Flutter'
  s.platform = :ios, '15.0'
  s.swift_version = '5.9'
  s.frameworks = 'Security', 'CryptoKit', 'DeviceCheck'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
end
