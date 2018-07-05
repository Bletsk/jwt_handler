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
    
    # Скипаем валидацию, если в контроллере аутентификации
    return if ['api/v1/auth'].include?(params[:controller]) || ['mail_auth'].include?(params[:controller])

    # Скипаем валидацию, если запрос в режиме дебага
    return p "JWT: Page rendered in debug-mode" if check_for_debug

    # @t = Thread.new do
    # Скипаем валидацию, если предоставлен секрет
    if request.headers['X-Authorization']
      
        begin
          headers = {
            "X-Authorization" => get_secret()
          }

          path = get_user_management_path + '/api/v1/auth/get_user_data_by_secret'
          response = HTTParty.get(path, :headers => headers, :timeout => 20)
          # p headers
          # p response
          if response.code.to_s.include?("20")
              return @user = JSON.parse(response.body)
          else
              p "JWT-handler: Page not found"
          end
        rescue HTTParty::Error => e
          p "JWT-handler: HTTParty error"
          p e.inspect
        rescue StandardError => e
          "JWT-handler: StandardError"
          p e.inspect
        end

        # return render json: {
        #   error: "X-Authorization error"
        # }, :status => 401
      end
        
      # Скипаем валидацию в development-окружении
      return if Rails.env.development? || Rails.env.test?

      jwt_validation_path = get_auth_service_path + '/api/v1/session/validate'
      referer = get_ref_link

      headers = {
        "Authorization" => get_jwt()
      }

      validation_response = HTTParty.post(jwt_validation_path, :headers => headers, body:{redirect_url:referer}, :timeout => 20)

      parsed_body = JSON.parse(validation_response.body)

      #checkout for token validationn response if it return error then redirect to the auth page
      if !parsed_body['error'].blank?

        redirect_url = parsed_body['sign_in_url']
        redirect_url += "?redirect_url=#{referer}" unless referer.to_s.blank?

        #checkout for ajax requests
        return redirect_to redirect_url unless request.headers['HTTP_ACCEPT'].include?("application/json") 
          
        render json:{redirect_url:redirect_url}, status: 302
      else
        #if jwt updated
        unless parsed_body['updated_token'].blank?
          cookies['JWT'] = { :value => parsed_body['updated_token'], :domain => get_domain_name, :path => '/' }
        end
      end
    # end
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
    p token
    return nil unless token || !token.to_s.empty?

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
          "organization_id" => "fdsf"
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
      ENV['jwt_user_management_path'] || ENV['user_management_url'] || 'http://localhost:3023'
    end

    def get_domain_name
      ENV['jwt_domain_name'] || 'localhost'
    end

    def check_for_debug
      uri = URI.parse(request.original_url)
      return uri.query && CGI.parse(uri.query)['jwt-debug'][0] == 'true'
    end

  end
end