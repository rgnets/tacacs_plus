require 'rubygems'
#Gem::manage_gems
require 'rake/gempackagetask'

spec = Gem::Specification.new do |s|
    s.platform  =   Gem::Platform::RUBY
    s.name      =   "tacacs_plus"
    s.description = "A Ruby based TACACS+ library"
    s.rubyforge_project = 'tacacs_plus'
    s.homepage = ''
    s.version   =   "1.1.0"
    s.author    =   "Dustin Spinhirne"
    s.email = ''
    s.summary   =   "TacacsPlus is a module and collection of classes for " +
                    "working with the TACACS+ protocol created by Cisco Systems Inc."
    s.files     =   FileList['lib/*.rb', 'test/*.rb', 'dialogs/**/*', 'scripts/**/*'].to_a
    s.require_path  =   "lib"
    s.test_files = Dir.glob('tests/*.rb')
    s.has_rdoc  =   true
    s.extra_rdoc_files  =   ["README"].concat(Dir.glob('doc/*'))
    s.add_dependency("netaddr", ">= 1.4.0")
end

Rake::GemPackageTask.new(spec) do |pkg|
    pkg.need_tar = true
end

task :test do
  require 'rake/runtest'
  Rake.run_tests('tests/*.rb')
end

task :default => "pkg/#{spec.name}-#{spec.version}.gem" do
   puts "generated latest version"
end
