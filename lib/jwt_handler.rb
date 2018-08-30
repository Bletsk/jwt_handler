require 'active_support/concern'
require 'jwt'
require 'httparty'

include ActionController::Helpers
include ActionController::MimeResponds
include ActionController::Cookies

# http://service-name - back-end путь
# /service-name - front-end путь


module JWTHandler
  extend ActiveSupport::Concern
  included do
    before_action :validate_token

    def validate_token
      
      # Скипаем валидацию, если в контроллере аутентификации
      return if ['api/v1/auth'].include?(params[:controller]) || ['mail_auth'].include?(params[:controller]) || ['password_reset'].include?(params[:controller]) || ['developer'].include?(params[:controller])

      # Скипаем валидацию, если запрос в режиме дебага
      return p "JWT: Page rendered in debug-mode" if check_for_debug

      # Скипаем валидацию, если предоставлен секрет
      if request.headers['X-Authorization']
        # logger.info "Обнаружен секрет. Проверяю..."
        
        headers = {
          "X-Authorization" => get_secret()
        }

        path = (Rails.env.beta? ? "http://" : "") + get_user_management_path + '/api/v1/auth/get_user_data_by_secret'
        logger.info "PATH"
        logger.info path

        response = HTTParty.get(path, :headers => headers, :timeout => 20)
        logger.info headers
        logger.info response
        if response.code.to_s.include?("20")
            return @user = JSON.parse(response.body)
        else
            # p "jwt: Секрет неверен"
            validate_jwt
        end
      else
        # logger.info "jwt: Секрет не задан"

        uri = URI.parse(request.original_url)
        token = CGI.parse(uri.query)['token'][0] if uri.query
        token = request.headers['token'] unless token
        
        if token
          redirect_url = (Rails.env.beta? ? "/" : "") +
            get_user_management_path + '/api/v1/auth/token/'+
            token + '?redirect_url=' + request.original_url.split('?').first

          return redirect_to redirect_url unless request.headers['HTTP_ACCEPT'].include?("application/json") 
          
          return render json:{redirect_url:redirect_url}, status: 302
        else
          validate_jwt
        end
      end
    end

    def validate_jwt
      return if (Rails.env.development? || Rails.env.test?) && !(ENV['jwt_ignore_dev'] == "true")

      # logger.info "jwt: Провожу классическую валидацию"

      return redirect_to_auth("JWT not found") if get_jwt().blank?

      jwt_validation_path = (Rails.env.beta? ? "http://" : "") + get_auth_service_path + '/api/v1/session/validate'
      
      referer = get_ref_link

      headers = {
        "Authorization" => get_jwt()
      }

      validation_response = HTTParty.post(jwt_validation_path, :headers => headers, body:{redirect_url:referer}, :timeout => 20)

      parsed_body = JSON.parse(validation_response.body)

      #checkout for token validationn response if it return error then redirect to the auth page
      if !parsed_body['error'].blank?
        redirect_to_auth(parsed_body['error'].to_s)

        # logger.error "Validation error: " + parsed_body['error'].to_s

        # redirect_url = "/" + get_auth_service_path
        # redirect_url += '?redirect_url=' + (request.original_url.split('?').first)
        # # redirect_url += '?redirect_url=' + (request.referer || request.original_url.split('?').first)

        # #checkout for ajax requests
        # return redirect_to redirect_url unless request.headers['HTTP_ACCEPT'].include?("application/json") 
          
        # render json:{redirect_url:redirect_url}, status: 302
      else
        #if jwt updated
        # logger.info "Валидация успешна"
        unless parsed_body['updated_token'].blank?
          cookies['JWT'] = Rails.env.beta? ?
            { :value => parsed_body['updated_token'], :path => '/' } :
            { :value => parsed_body['updated_token'], :domain => get_domain_name, :path => '/' }
        end
      end
    end

    def get_jwt
      #Remember that JWT structure is "JWT <token>"
      begin
        return request.headers['Authorization'] || request.cookies["JWT"] || ""
      rescue
        return nil
      end
    end

    def get_secret
      return request.headers['X-Authorization'] || request.headers['x-authorization'] || ""
    end

    def extract_jwt_payload
      token = get_jwt #"JWT <token>" split on
      # p "token"
      # p token
      return nil if !token || token.to_s.empty?

      return JWT.decode(token, nil, false)[0]
    end

    # Запрашиваем данные текущего пользователя
    def current_user
      if request.headers['X-Authorization']
        # @t.join
        return @user if @user
      else
        payload = extract_jwt_payload
        return payload['user'].to_h unless payload.nil?
        
        if Rails.env.development? || Rails.env.test? || check_for_debug
          return {
            "id" => "70577a3f-32a4-4c63-affa-13331998ba7e",
            "fname" => "User",
            "lname" => "test",
            "roles" => ["auto", "student", "trainer", "methodologist", "manager", "admin"], # student, trainer, methodologist, manager, admin
            "organization_id" => "70577a3f-32a4-4c63-affa-13331998ba7e",
            "pro" => true,
            "groups" => []
          }
        end
      end

      return {}
    end

    private
    def get_ref_link
      ENV['jwt_referer_link'] || Rails.root
    end

    def get_auth_service_path
      ENV['jwt_auth_service_path'] || 'http://localhost:3001'
    end

    def get_user_management_path
      value = ENV['jwt_user_management_path'] || ENV['user_management_url'] || 'http://localhost:3023'
      value = value[1..-1] if value.first == '/'
      return value
    end

    # deprecated
    # def get_domain_name
    #   ENV['jwt_domain_name'] || 'localhost'
    # end

    def check_for_debug
      uri = URI.parse(request.original_url)
      return uri.query && CGI.parse(uri.query)['jwt-debug'][0] == 'true'
    end

    def redirect_to_auth(error)
      logger.error "Validation error: " + error
      # logger.info request.original_url
      # puts request.original_url

      if Rails.env.beta?
        redirect_url = "/#{get_auth_service_path}?redirect_url=#{ENV['RAILS_RELATIVE_URL_ROOT']}#{request.fullpath}"
      else
        redirect_url = get_auth_service_path + '?redirect_url=' + (request.original_url.split('?').first)
      end

      #checkout for ajax requests
      return redirect_to redirect_url unless request.headers['HTTP_ACCEPT'].include?("application/json") 
        
      render json:{redirect_url:redirect_url}, status: 302
    end
  end
end