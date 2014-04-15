class Hiera
  module Backend
    class Http_backend

      def initialize
        require 'net/http'
        require 'net/https'
        @config = Config[:http]

        @http = Net::HTTP.new(@config[:host], @config[:port])
        @http.read_timeout = @config[:http_read_timeout] || 10
        @http.open_timeout = @config[:http_connect_timeout] || 10

        if @config[:use_ssl]
          @http.use_ssl = true
          if @config[:ssl_cert]
            @http.verify_mode = OpenSSL::SSL::VERIFY_PEER
            store = OpenSSL::X509::Store.new
            store.add_cert(OpenSSL::X509::Certificate.new(File.read(@config[:ssl_ca_cert])))
            @http.cert_store = store

            @http.key = OpenSSL::PKey::RSA.new(File.read(@config[:ssl_cert]))
            @http.cert = OpenSSL::X509::Certificate.new(File.read(@config[:ssl_key]))
          end
        else
          @http.use_ssl = false
        end

        @keyfile  = @config[:keyfile]
        @certfile = @config[:certfile]

        # we will read in the key and the cert
        # then we will create a cipher object to use
        if @keyfile && @certfile
          @key  = OpenSSL::PKey::RSA.new File.read(@keyfile)
          @cert = OpenSSL::X509::Certificate.new File.read(@certfile)
        end
      end

      def lookup(key, scope, order_override, resolution_type)

        answer = nil

        paths = @config[:paths].map { |p| Backend.parse_string(p, scope, { 'key' => key }) }
        paths.insert(0, order_override) if order_override


        paths.each do |path|

          Hiera.debug("[hiera-http]: Lookup #{key} from #{@config[:host]}:#{@config[:port]}#{path}")
          httpreq = Net::HTTP::Get.new(path)

          begin
            httpres = @http.request(httpreq)
          rescue Exception => e
            Hiera.warn("[hiera-http]: Net::HTTP threw exception #{e.message}")
            raise Exception, e.message unless @config[:failure] == 'graceful'
            next
          end

          unless httpres.kind_of?(Net::HTTPSuccess)
            Hiera.debug("[hiera-http]: bad http response from #{@config[:host]}:#{@config[:port]}#{path}")
            Hiera.debug("HTTP response code was #{httpres.code}")
            raise Exception, 'Bad HTTP response' unless @config[:failure] == 'graceful'
            next
          end

          result = self.parse_response(key, httpres.body)
          next unless result

          parsed_result = Backend.parse_answer(result, scope)

          case resolution_type
          when :array
            answer ||= []
            answer << parsed_result
          when :hash
            answer ||= {}
            answer = parsed_result.merge answer
          else
            answer = parsed_result
            break
          end
        end
        answer
      end


      def parse_response(key,answer)

        return nil unless answer

        Hiera.debug("[hiera-http]: Query returned data, parsing response as #{@config[:output] || 'plain'}")

        case @config[:output]

        when 'json'
          # If JSON is specified as the output format, assume the output of the
          # endpoint URL is a JSON document and return keypart that matched our
          # lookup key
          self.json_handler(key,answer)
        when 'yaml'
          # If YAML is specified as the output format, assume the output of the
          # endpoint URL is a YAML document and return keypart that matched our
          # lookup key
          self.yaml_handler(key,answer)
        else
          # When the output format is configured as plain we assume that if the
          # endpoint URL returns an HTTP success then the contents of the response
          # body is the value itself, or nil.
          #
          answer
        end
      end

      # Handlers
      # Here we define specific handlers to parse the output of the http request
      # and return a value.  Currently we support YAML and JSON
      #
      def json_handler(key, answer)
        require 'json'
        self.decrypt(JSON.parse(answer)[key])
      end

      def yaml_handler(key, answer)
        require 'yaml'
        self.decrypt(YAML.load(answer)[key])
      end

      def decrypt(answer)
        if @keyfile && @certfile
          require 'base64'
          if a = /ENC\[([^,]+),([^\]]+)\]/.match(answer)
            # right now we only support PKCS7 (using a little 
            #   reflective programming we can remedy this)
            if a[1] != 'PKCS7'
              fail 'At this time the only supported algorithm is PKCS7'
            end
            
            # we are good to decrypt
            (OpenSSL::PKCS7.new Base64.decode64 a[2]).decrypt @key, @cert
          else
            answer
          end
        else
          answer
        end
      end

    end
  end
end

