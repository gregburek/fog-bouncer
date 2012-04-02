module Fog
  module Bouncer
    class Source
      attr_reader :group, :source
      attr_accessor :local, :remote

      def self.log(data, &block)
        Fog::Bouncer.log({ source: true }.merge(data), &block)
      end

      def log(data, &block)
        self.class.log({ source: source }.merge(data), &block)
      end

      def initialize(source, group, &block)
        @source = source
        @group = group
        @local = false
        @remote = false
        if block_given?
          @local = true
          @wrap_local = true
          instance_eval(&block)
          @wrap_local = false
        end
      end

      def extras
        protocols.select { |protocol| !protocol.local? }
      end

      def from_ip_protocol(protocol, from, to)
        if %w( icmp tcp udp ).include? protocol
          p = protocols.find { |p| p.type == protocol && p.from == from && p.to == to }
          if p.nil?
            p = send("#{protocol}_protocol", Range.new(from, to))
            protocols << p
          end
          p.remote = true
          p
        else
          # raise
        end
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

      def remote?
        remote
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
        ports.each { |port| protocols << icmp_protocol(port) }
      end

      def icmp_protocol(port)
        Fog::Bouncer::Protocols::ICMP.new(port, self, @wrap_local)
      end

      def tcp(*ports)
        ports.each { |port| protocols << tcp_protocol(port) }
      end

      def tcp_protocol(port)
        Fog::Bouncer::Protocols::TCP.new(port, self, @wrap_local)
      end

      def udp(*ports)
        ports.each { |port| protocols << udp_protocol(port) }
      end

      def udp_protocol(port)
        Fog::Bouncer::Protocols::UDP.new(port, self, @wrap_local)
      end
    end
  end
end
