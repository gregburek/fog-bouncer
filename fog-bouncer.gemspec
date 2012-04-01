# -*- encoding: utf-8 -*-
require File.expand_path('../lib/fog/bouncer/version', __FILE__)

Gem::Specification.new do |gem|
  gem.authors       = ["Dylan Egan"]
  gem.email         = ["dylanegan@gmail.com"]
  gem.description   = %q{A simple way to define and manage security groups for AWS through fog.}
  gem.summary       = %q{A simple way to define and manage security groups for AWS through fog.}
  gem.homepage      = ""

  gem.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  gem.files         = `git ls-files`.split("\n")
  gem.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  gem.name          = "fog-bouncer"
  gem.require_paths = ["lib"]
  gem.version       = Fog::Bouncer::VERSION

  gem.add_dependency "clamp", "~> 0.3.0"
  gem.add_dependency "fog", "~> 1.2.0"
  gem.add_dependency "rake"
  gem.add_dependency "scrolls", "~> 0.0.5"

  gem.add_development_dependency "minitest"
end
