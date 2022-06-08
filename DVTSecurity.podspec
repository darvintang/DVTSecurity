Pod::Spec.new do |s|
  s.name             = 'DVTSecurity'
  s.version          = '1.0'
  s.summary          = 'DVTSecurity'

  s.description      = <<-DESC
  TODO:
    DVTSecurity
  DESC

  s.homepage         = 'https://github.com/darvintang/DVTSecurity'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'xt-input' => 'input@tcoding.cn' }
  s.source           = { :git => 'https://github.com/darvintang/DVTSecurity.git', :tag => s.version.to_s }

  s.ios.deployment_target = '12.0'

  s.source_files = 'Sources/**/*.swift'
  s.swift_version = '5'
  s.requires_arc  = true
  s.dependency 'SwiftyRSA'
end
