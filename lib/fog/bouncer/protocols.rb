module Fog
  module Bouncer
    class Protocol
      attr_reader :from, :to

      def initialize(port, source)
        if port.is_a?(Range)
          @from = port.begin
          @to = port.end
        else
          @from = port
          @to = port
        end

        @source = source
      end
    end

    module Protocols
      class ICMP < Protocol
        def initialize(port, source)
          super

          @from = @to = -1 if port == -1
        end
      end

      class TCP < Protocol
      end

      class UDP < Protocol
      end
    end
  end
end
