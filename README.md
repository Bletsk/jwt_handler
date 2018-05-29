# JwtHandler
Simple Token handler for back-end ruby micro-services.

## Usage
Include jwt_handler in your application_controller.rb and pass it links for authorization server and default referer and also name of domain (if needed):
```ruby
include 'JWThandler'
jwt_parameters ref_link: 'http://default-referer-url', validation_path: 'http://path-to-validate', domain_name: '.domain.name.com' 
```

Additionally, instead of ref_link you can specify controller and method for default refering:
```ruby
jwt_parameters controller: 'controller-name', action: 'action-name', id: 'optional-id'
```

## Installation
Add this line to your application's Gemfile:

```ruby
gem 'jwt_handler'
```

And then execute:
```bash
$ bundle
```

Or install it yourself as:
```bash
$ gem install jwt_handler
```

## Contributing
Contribution directions go here.

## License
The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
