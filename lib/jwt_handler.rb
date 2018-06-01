require 'active_support/concern'
require 'jwt'
require 'httparty'

module JWTHandler
  extend ActiveSupport::Concern
  included do

  	include ActionController::Helpers
  	include ActionController::MimeResponds
	include ActionController::Cookies
    before_action :validate_token

    module ClassMethods
	    attr_reader :arguable_opts

	    private
	    def jwt_parameters(opts={})
	    	@arguable_opts = opts
	    end
	end

    def validate_token
  		return if ['api/v1/auth'].include?(params[:controller])

		jwt_validation_path = get_validation_path_from_opts
		referer = get_ref_link_from_opts

		headers = { 
		"Authorization"  => get_jwt()
		}

		validation_response = HTTParty.post(jwt_validation_path, :headers => headers, body:{redirect_url:referer})

		parsed_body = JSON.parse(validation_response.body)

		#checkout for token validationn response if it return error then redirect to the auth page
		if !parsed_body['error'].blank?
			# p "parsed_body error"

			redirect_url = parsed_body['sign_in_url']
			if !referer.to_s.blank?
				redirect_url += "?redirect_url=#{referer}" #we have to send back redirection url
			end

			if !request.headers['HTTP_ACCEPT'].include?("application/json") #checkout for ajax requests
				redirect_to redirect_url
			else
				render json:{redirect_url:redirect_url}, status: 302
			end

			# respond_to do |format|
			# 	format.json {
			# 		render json: {
			#         	error: "Error: Not authorized \\ Wrong token"
			# 		}, :status => 401
			# 	}
			# 	format.html {
			# 		redirect_url = parsed_body['sign_in_url']
			# 		if !referer.to_s.blank?
			# 			redirect_url += "?redirect_url=#{referer}" #we have to send back redirection url
			# 		end

			# 		if !request.headers['HTTP_ACCEPT'].include?("application/json") #checkout for ajax requests
			# 			redirect_to redirect_url
			# 		else
			# 			render json:{redirect_url:redirect_url}, status: 302
			# 		end
			# 	}
			# end
		else
			if !parsed_body['updated_token'].blank? #if jwt updated
			    cookies['JWT'] = response.set_cookie "JWT", { :value => parsed_body['updated_token'], :domain => get_domain_name_from_opts}
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
  		return extract_jwt_payload['user']
		end

	#Получаем данные из переданных аргументов
	private
	def get_arguable_opts
	    if self.class.arguable_opts.blank? && self.class.superclass.arguable_opts.present?
	    	opts = self.class.superclass.arguable_opts
	    elsif self.class.arguable_opts.present? && self.class.superclass.arguable_opts.present?
	    	opts = self.class.superclass.arguable_opts.merge(self.class.arguable_opts)
	    else
	    	opts = self.class.arguable_opts
	    end
	    opts || {}
  	end

  	#Проверяем в параметрах наличие реферальной ссылки
  	private
  	def get_ref_link_from_opts
  		opts = get_arguable_opts
  		unless opts[:ref_link].to_s.blank?
  			return opts[:ref_link]
  		end

  		if !opts[:controller].to_s.blank? && !opts[:action].to_s.blank?
  			if !opts[:id].to_s.blank?
  				return url_for(controller: opts[:controller], action: opts[:action], id: opts[:id])
  			end

  			return url_for(controller: opts[:controller], action: opts[:action])
  		end

  		return 'http://localhost:3000/organization'
  	end

  	#Проверяем в параметрах наличие ссылки на сервер валидации
  	def get_validation_path_from_opts
  		opts = get_arguable_opts

  		unless opts[:validation_path].to_s.blank?
  			return opts[:validation_path]
  		end

  		return 'http://localhost:3001/api/v1/session/validate'
  	end

  	# Проверяем в параметрах наличие имени домена
  	def get_domain_name_from_opts
  		opts = get_arguable_opts

  		unless opts[:domain_name].to_s.blank?
  			return opts[:domain_name]
  		end

  		return 'localhost'
  	end
  end
end