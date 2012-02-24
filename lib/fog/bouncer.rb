require "fog"
require "fog/bouncer/version"

module Fog
  module Bouncer
    def self.fog
      @fog ||= Fog::Compute.new(
        :provider => "AWS",
        :region => (ENV['PROVIDER_REGION'] || 'us-east-1'),
        :aws_access_key_id => ENV['AWS_ACCESS_KEY_ID'],
        :aws_secret_access_key => ENV['AWS_SECRET_ACCESS_KEY']
      )
    end

    def self.security(&block)
      Fog::Bouncer::Security.new(&block)
    end

    class Security
      def initialize(&block)
        instance_eval(&block)
      end

      def groups
        @groups ||= []
      end

      def group(name, description, &block)
        groups << Group.new(name, description, &block)
      end
    end

    class Group
      attr_reader :name, :description

      def initialize(name, description, &block)
        @name = name
        @description = description
        instance_eval(&block) if block_given?
      end

      def sources
        @sources ||= []
      end

      def source(source, &block)
        sources << Sources.for(source, &block)
      end
    end

    class Sources
      def self.for(source, &block)
        if source =~ /^\d+\.\d+\.\d+.\d+\/\d+$/
          CIDRSource.new(source, &block)
        else
          GroupSource.new(source, &block)
        end
      end
    end

    class Source
      def initialize(source, &block)
        @source = source
        instance_eval(&block) if block_given?
      end

      def protocols
        @protocols ||= { icmp: [], tcp: [], udp: [] }
      end

      def icmp(*ports)
        ports.each { |port| protocols[:icmp] << ICMP.new(port) }
      end

      def tcp(*ports)
        ports.each { |port| protocols[:tcp] << TCP.new(port) }
      end

      def udp(*ports)
        ports.each { |port| protocols[:udp] << UDP.new(port) }
      end
    end

    class CIDRSource < Source
      def range
        @source
      end
    end

    class Protocol
      attr_reader :from, :to

      def initialize(port)
        if port.is_a?(Range)
          @from = port.begin
          @to = port.end
        else
          @from = port
        end
      end
    end

    class ICMP < Protocol
    end

    class TCP < Protocol
    end

    class UDP < Protocol
    end
  end
end
