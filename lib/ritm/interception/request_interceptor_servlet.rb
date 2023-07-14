require 'webrick'

module Ritm
  # Actual implementation of the SSL Reverse Proxy service (decoupled from the certificate handling)
  class RequestInterceptorServlet < WEBrick::HTTPServlet::AbstractServlet
    def initialize(server, forwarder)
      super server
      @forwarder = forwarder
    end

    def service(request, response)
      p "Gem RequestInterceptorServlet - service"
      @forwarder.forward(request, response)
    end
  end
end
