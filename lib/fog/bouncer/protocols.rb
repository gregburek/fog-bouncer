module Fog
  module Bouncer
    class Protocol
      attr_reader :from, :local, :remote, :source, :to
      attr_accessor :local, :remote

      def initialize(port, source, local = false)
        if port.is_a?(Range)
          @from = port.begin
          @to = port.end
        else
          @from = port
          @to = port
        end

        @local = local
        @source = source
      end

      def local?
        local
      end

      def remote?
        remote
      end

      def type
        @type ||= self.class.to_s.gsub("Fog::Bouncer::Protocols::", "").downcase
      end

      def ==(other)
        type == other.type &&
        from == other.from &&
        to == other.to
      end

      def <=>(other)
        [from, to] <=> [other.from, other.to]
      end

      def inspect
        "<#{self.class.name} @from=#{from.inspect} @to=#{to.inspect}>"
      end

      def to_log
        { source: source.source, protocol: type, from: from, to: to }
      end
    end

    module Protocols
      class ICMP < Protocol
        def initialize(port, source, local = false)
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
