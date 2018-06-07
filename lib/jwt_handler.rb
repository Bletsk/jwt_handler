require 'active_support/concern'
require 'jwt'
require 'httparty'

include ActionController::Helpers
include ActionController::MimeResponds
include ActionController::Cookies

module JWTHandler
  extend ActiveSupport::Concern
  included do
    before_action :validate_token

    def validate_token
  		return if ['api/v1/auth'].include?(params[:controller])

		jwt_validation_path = get_auth_service_path + '/api/v1/session/validate'
		referer = get_ref_link

		headers = { 
			"Authorization" => get_jwt()
		}

		validation_response = HTTParty.post(jwt_validation_path, :headers => headers, body:{redirect_url:referer})

		parsed_body = JSON.parse(validation_response.body)

		#checkout for token validationn response if it return error then redirect to the auth page
		if !parsed_body['error'].blank?

			redirect_url = parsed_body['sign_in_url']
			if !referer.to_s.blank?
				redirect_url += "?redirect_url=#{referer}" #we have to send back redirection url
			end

			if !request.headers['HTTP_ACCEPT'].include?("application/json") #checkout for ajax requests
				redirect_to redirect_url
			else
				render json:{redirect_url:redirect_url}, status: 302
			end
		else
			if !parsed_body['updated_token'].blank? #if jwt updated
				cookies['JWT'] = response.cookies['JWT'] = { :value => parsed_body['updated_token'], :domain => get_domain_name, :path => '/' }
		    end
		end
	end

	def get_jwt
		#Remember that JWT structure is "JWT <token>"
		return cookies["JWT"] || request.headers['Authorization'] || ""
	end

	def extract_jwt_payload
		token = get_jwt.split('bearer ')[1] #"JWT <token>" split on
		return JWT.decode(token, nil, false)[0]
	end

	def current_user
  		return extract_jwt_payload['user'].to_h
	end

  	private
  	def get_ref_link
  		ENV['jwt_referer_link'] || Rails.root
  	end

  	def get_auth_service_path
  		ENV['jwt_auth_service_path'] || 'http://localhost:3001'
  	end

  	def get_domain_name
  		ENV['jwt_domain_name'] || 'localhost'
  	end

  end
end