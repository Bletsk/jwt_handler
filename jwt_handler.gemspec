$:.push File.expand_path("../lib", __FILE__)

# Maintain your gem's version:
require "jwt_handler/version"

# Describe your gem and declare its dependencies:
Gem::Specification.new do |s|
  s.name        = "jwt_handler"
  s.version     = JwtHandler::VERSION
  s.authors     = ["Bletsk"]
  s.email       = ["s.tomashevsky@oblakogroup.ru"]
  s.homepage    = "http:/oblakogroup.ru"
  s.summary     = "JWT Handler"
  s.description = "Handles JWT for user authentification of TrainingSpace app."
  s.license     = "MIT"

  s.files = Dir["{app,config,db,lib}/**/*", "MIT-LICENSE", "Rakefile", "README.md"]

  s.add_dependency "rails", "~> 5.1.6"

  s.add_development_dependency "sqlite3"
end
