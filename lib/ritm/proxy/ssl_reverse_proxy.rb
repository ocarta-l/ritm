require 'ritm/helpers/patches'
require 'ritm/interception/request_interceptor_servlet'
require 'ritm/proxy/cert_signing_https_server'
require 'ritm/certs/certificate'

module Ritm
  module Proxy
    # SSL Intercept reverse proxy server. Supports interception of https request and responses
    # It does man-in-the-middle with on-the-fly certificate signing using the given CA
    class SSLReverseProxy
      # Creates a HTTPS server with the given settings
      # @param port [Fixnum]: TCP port to bind the service
      # @param ca [Ritm::CA]: The certificate authority used to sign fake server certificates
      # @param forwarder [Ritm::HTTPForwarder]: Forwards http traffic with interception
      def initialize(port, ca, forwarder)
        p "Gem SSLReverseProxy - initialize"
        @ca = ca
        default_vhost = '0.0.0.0'
        @server = CertSigningHTTPSServer.new(Port: port,
                                             AccessLog: [],
                                             Logger: WEBrick::Log.new(File.open("plop2.txt", 'w'), 5),
                                             ca: ca,
                                             **vhost_settings(default_vhost))
        @server.mount '/', RequestInterceptorServlet, forwarder
      end

      def start_async
        trap(:TERM) { shutdown }
        trap(:INT) { shutdown }
        Thread.new { @server.start }
      end

      def shutdown
        @server.shutdown
      end

      private

      def gen_signed_cert(common_name)
        p "Gem SSLReverseProxy - gen_signed_cert"
        cert = Ritm::Certificate.create(common_name)
        @ca.sign(cert)
        cert
      end

      def vhost_settings(hostname)
        p "Gem SSLReverseProxy - vhost_settings"
        cert = gen_signed_cert(hostname)
        {
          ServerName: hostname,
          SSLEnable: true,
          SSLVerifyClient: OpenSSL::SSL::VERIFY_NONE,
          SSLPrivateKey: OpenSSL::PKey::RSA.new(cert.private_key),
          SSLCertificate: OpenSSL::X509::Certificate.new(cert.pem),
          SSLCertName: [['CN', hostname]]
        }
      end
    end
  end
end
