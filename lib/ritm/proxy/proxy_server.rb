require 'webrick'
require 'webrick/httpproxy'
require 'ritm/helpers/patches'

module Ritm
  module Proxy
    # Proxy server that accepts request and response intercept handlers for HTTP traffic
    # HTTPS traffic is redirected to the SSLReverseProxy for interception
    class ProxyServer < WEBrick::HTTPProxyServer
      def start_async
        trap(:TERM) { shutdown }
        trap(:INT) { shutdown }
        Thread.new { start }
      end

      # Override
      # Patches the destination address on HTTPS connections to go via the HTTPS Reverse Proxy
      def do_CONNECT(req, res)
        p "Gem ProxyServer - do_CONNECT - before"
        p @config[:https_forward].inspect
        p req.unparsed_uri
        p ssl_pass_through? req.unparsed_uri
        p "Gem ProxyServer - do_CONNECT - middle"
        req.unparsed_uri = @config[:https_forward] unless ssl_pass_through? req.unparsed_uri
        super
        p "Gem ProxyServer - do_CONNECT - after"
      end

      # Override
      # Handles HTTP (no SSL) traffic interception
      def proxy_service(req, res)
        p "Gem ProxyServer - proxy_service"
        # Proxy Authentication
        proxy_auth(req, res)
        @config[:forwarder].forward(req, res)
      end

      # Override
      def proxy_uri(req, _res)
        p "Gem ProxyServer - proxy_uri"
        if req.request_method == 'CONNECT'
          # Let the reverse proxy handle upstream proxies for https
          nil
        else
          proxy = @config[:ritm_conf].misc.upstream_proxy
          proxy.nil? ? nil : URI.parse(proxy)
        end
      end

      private

      def ssl_pass_through?(destination)
        p "Gem ProxyServer - ssl_pass_through"
        @config[:ritm_conf].misc.ssl_pass_through.each do |matcher|
          case matcher
          when String
            return true if destination == matcher
          when Regexp
            return true if destination =~ matcher
          end
        end
        false
      end
    end
  end
end
