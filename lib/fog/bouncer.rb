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

      def accounts
        @accounts ||= {}
      end

      def account(name, account_id)
        accounts[name] = account_id
      end

      def groups
        @groups ||= []
      end

      def group(name, description, &block)
        groups << Group.new(name, description, self, &block)
      end
    end

    class Group
      attr_reader :name, :description, :security

      def initialize(name, description, security, &block)
        @name = name
        @description = description
        @security = security
        instance_eval(&block) if block_given?
      end

      def sources
        @sources ||= []
      end

      def source(source, &block)
        sources << Sources.for(source, self, &block)
      end
    end

    class Source
      attr_reader :group

      def initialize(source, group, &block)
        @source = source
        @group = group
        instance_eval(&block) if block_given?
      end

      def protocols
        @protocols ||= { icmp: [], tcp: [], udp: [] }
      end

      def icmp(*ports)
        ports.each { |port| protocols[:icmp] << Fog::Bouncer::Protocols::ICMP.new(port, self) }
      end

      def tcp(*ports)
        ports.each { |port| protocols[:tcp] << Fog::Bouncer::Protocols::TCP.new(port, self) }
      end

      def udp(*ports)
        ports.each { |port| protocols[:udp] << Fog::Bouncer::Protocols::UDP.new(port, self) }
      end
    end

    module Sources
      def self.for(source, group, &block)
        if source =~ /^\d+\.\d+\.\d+.\d+\/\d+$/
          CIDR.new(source, group, &block)
        else
          Group.new(source, group, &block)
        end
      end

      class CIDR < Fog::Bouncer::Source
        def range
          @source
        end
      end

      class Group < Fog::Bouncer::Source
        attr_reader :user_id, :user_alias, :name

        def initialize(source, group, &block)
          super
          case source
          when /^(.+)@(.+)$/
            @name = $1
            @user_alias = $2
          when /^@(.+)$/
            @user_alias = $1
          else
            @name = source
          end
        end

        def user_id
          group.security.accounts[user_alias]
        end
      end
    end

    class Protocol
      attr_reader :from, :to

      def initialize(port, source)
        if port.is_a?(Range)
          @from = port.begin
          @to = port.end
        else
          @from = port
        end

        @source = source
      end
    end

    module Protocols
      class ICMP < Protocol
      end

      class TCP < Protocol
      end

      class UDP < Protocol
      end
    end
  end
end
