# JwtHandler
Simple Token handler for back-end ruby micro-services.

## Usage
Include jwt_handler in your application_controller.rb and put links for authorization server and default referer and also name of domain (if needed) into your environment variables(application.yml):
```ruby
include 'JWThandler'
```

```ruby
development:
	jwt_referer_link: "http://training.api.oblako.com:3002/api/v1/room/1"
	jwt_auth_service_path: "http://auth.oblako.com:3001"
	jwt_domain_name: ".oblako.com"
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
