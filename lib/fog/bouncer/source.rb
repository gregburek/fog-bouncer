module Fog
  module Bouncer
    class Source
      attr_reader :group, :source
      attr_writer :local, :remote

      def initialize(source, group, &block)
        @source = source
        @group = group
        if block_given?
          @local = true
          instance_eval(&block)
        end
      end

      def extras
        protocols.select { |protocol| !protocol.local? }
      end

      def add_protocol(type, port)
        from, to = Protocol.range(port)
        protocol = protocols.find { |p| p.type == type && p.from == from && p.to == to }
        if protocol.nil?
          protocol = case type.to_sym
          when :icmp
            Fog::Bouncer::Protocols::ICMP.new(port, self)
          when :tcp
            Fog::Bouncer::Protocols::TCP.new(port, self)
          when :udp
            Fog::Bouncer::Protocols::UDP.new(port, self)
          end

          protocols << protocol
        end

        protocol
      end

      def local
        @local ||= false
      end

      def local?
        !!local
      end

      def missing
        protocols.select { |protocol| protocol.local? && !protocol.remote? }
      end

      def protocols
        @protocols ||= []
      end

      def protocols=(protocols)
        @protocols = protocols
      end

      def remote
        @remote ||= false
      end

      def remote?
        !!remote
      end

      def ==(other)
        source == other.source &&
        group == other.group &&
        protocols.sort! == other.protocols.sort!
      end

      def inspect
        "<#{self.class.name} @source=#{source.inspect} @local=#{local} @remote=#{remote} @protocols=#{protocols.inspect}>"
      end

      private

      def icmp(*ports)
        ports.each { |port| p = add_protocol(:icmp, port); p.local = true }
      end

      def tcp(*ports)
        ports.each { |port| p = add_protocol(:tcp, port); p.local = true }
      end

      def udp(*ports)
        ports.each { |port| p = add_protocol(:udp, port); p.local = true }
      end
    end
  end
end
