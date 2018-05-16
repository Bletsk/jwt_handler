require 'active_support/concern'

module JWTHandler
  extend ActiveSupport::Concern
  included do

  	include HTTParty
    before_action :validate_token


    def validate_token
  	  return if ['api/v1/auth'].include?(params[:controller])

      # default_redirect_url = 'http://localhost:3000/organization/1'
      default_redirect_url = 'http://localhost:3000/organization'
      jwt_validation_path = 'http://localhost:3001/api/v1/session/validate'

      # puts "ACHTUNG"
      # request.referer
      # referer = request.referer || default_redirect_url
      referer = default_redirect_url

      headers = { 
        "Authorization"  => get_jwt()
      }
      #Request for validating and updating jwt
      validation_response = HTTParty.post(jwt_validation_path, :headers => headers, body:{redirect_url:referer})

      parsed_body = JSON.parse(validation_response.body)
      #checkout for token validationn response if it return error then redirect to the auth page
      if !parsed_body['error'].blank?
        p 'parsed_body error'

        redirect_url = parsed_body['sign_in_url'] + "?redirect_url=#{referer}" #we have to send back redirection url

        if !request.headers['HTTP_ACCEPT'].include?("application/json") #checkout for ajax requests
        	redirect_to redirect_url
        else
        	render json:{redirect_url:redirect_url}, status: 302
        end
      else
      	if !parsed_body['updated_token'].blank? #if jwt updated
	      	 # cookies['JWT'] = request.cookies["JWT"] = {:value => parsed_body['updated_token'], domain: 'localhost'}
           # puts 'Creating cookies' + cookies['JWT'].to_json
			     cookies['JWT'] = response.set_cookie "JWT", { :value => parsed_body['updated_token'], domain: 'localhost'}
		    end
        # p "Token valid"
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
      		return extract_jwt_payload['user']
  	end

  end
end