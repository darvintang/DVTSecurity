Pod::Spec.new do |s|
  s.name             = 'DVTSecurity'
  s.version          = '3.0.0'
  s.summary          = 'DVTSecurity'

  s.description      = <<-DESC
  TODO:
    来自SwiftyRSA，移除OC支持，添加SMP配置使用
  DESC

  s.homepage         = 'https://github.com/darvintang/DVTSecurity'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'darvin' => 'darvin@tcoding.cn' }
  s.source           = { :git => 'https://github.com/darvintang/DVTSecurity.git', :tag => s.version.to_s }

  s.ios.deployment_target = '13'
  s.osx.deployment_target = '11'

  s.source_files = 'Sources/**/*.swift'
  s.frameworks = 'Security'
  
  s.swift_version = '5'
  s.requires_arc  = true
end
