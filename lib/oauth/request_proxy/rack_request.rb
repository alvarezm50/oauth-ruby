require 'oauth/request_proxy/base'
require 'uri'
require 'rack'

module OAuth::RequestProxy
  class RackRequest < OAuth::RequestProxy::Base
    proxies Rack::Request

    def method
      request.env["rack.methodoverride.original_method"] || request.request_method
    end

    def uri
      request.url
    end

    # Override from OAuth::RequestProxy::Base to avoid roundtrip
    # conversion to Hash or Array and thus preserve the original
    # parameter names
    def parameters_for_signature
      params = []
      params << options[:parameters].to_query if options[:parameters]

      unless options[:clobber_request]
        params << header_params.to_query
        params << request.query_string unless request.query_string.blank?
        if request.post? && request.content_type == Mime::Type.lookup("application/x-www-form-urlencoded")
          params << request.raw_post
        end
      end

      params.
        join('&').split('&').
        reject(&:blank?).
        map { |p| p.split('=').map{|esc| CGI.unescape(esc)} }.
        reject { |kv| kv[0] == 'oauth_signature'}
    end

    def parameters
      if options[:clobber_request]
        options[:parameters] || {}
      else
        params = request_params.merge(query_params).merge(header_params)
        params.merge(options[:parameters] || {})
      end
    end

    def signature
      parameters['oauth_signature']
    end

  protected

    def query_params
      request.GET
    end

    def request_params
      request.POST
    end
  end
end
