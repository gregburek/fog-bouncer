module Fog
  module Bouncer
    class Source
      attr_reader :group, :source

      def self.log(data, &block)
        Fog::Bouncer.log({ source: true }.merge(data), &block)
      end

      def log(data, &block)
        self.class.log({ source: source }.merge(data), &block)
      end

      def initialize(source, group, &block)
        @source = source
        @group = group
        instance_eval(&block) if block_given?
      end

      def clone(protocols)
        log(clone: true) do
          clone = self.class.new(source, group)
          clone.protocols = protocols
          clone
        end
      end

      def extras
        extras = []

        remote.protocols.each do |protocol|
          unless has_protocol?(protocol)
            extras << protocol
          end
        end

        extras
      end

      def extras?
        extras.any?
      end

      def has_protocol?(protocol_to_find)
        found = protocols.find do |protocol|
          protocol == protocol_to_find
        end

        !found.nil?
      end

      def missing
        missing = []

        return missing unless remote

        protocols.each do |protocol|
          unless remote.has_protocol?(protocol)
            missing << protocol
          end
        end

        missing
      end

      def missing?
        missing.any?
      end

      def protocols
        @protocols ||= []
      end

      def protocols=(protocols)
        @protocols = protocols
      end

      def remote
        group.remote.sources.find { |s| s.source == source } if group.remote
      end

      def ==(other)
        source == other.source &&
        group == other.group &&
        protocols.sort! == other.protocols.sort!
      end

      def inspect
        "<#{self.class.name} @source=#{source.inspect} @protocols=#{protocols.inspect}>"
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
