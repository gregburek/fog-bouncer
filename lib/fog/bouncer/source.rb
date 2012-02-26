module Fog
  module Bouncer
    class Source
      attr_reader :group

      def initialize(source, group, &block)
        @source = source
        @group = group
        instance_eval(&block) if block_given?
      end

      def protocols
        @protocols ||= []
      end

      private

      def icmp(*ports)
        ports.each { |port| protocols << Fog::Bouncer::Protocols::ICMP.new(port, self) }
      end

      def tcp(*ports)
        ports.each { |port| protocols << Fog::Bouncer::Protocols::TCP.new(port, self) }
      end

      def udp(*ports)
        ports.each { |port| protocols << Fog::Bouncer::Protocols::UDP.new(port, self) }
      end
    end
  end
end
