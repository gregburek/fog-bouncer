require "fog"
require "fog/bouncer/version"

module Fog
  module Bouncer
    def self.doorlists
      @doorlists ||= []
    end

    def self.fog
      @fog ||= Fog::Compute.new(
        :provider => "AWS",
        :region => (ENV['PROVIDER_REGION'] || 'us-east-1'),
        :aws_access_key_id => ENV['AWS_ACCESS_KEY_ID'],
        :aws_secret_access_key => ENV['AWS_SECRET_ACCESS_KEY']
      )
    end

    def self.security(&block)
      doorlists << Fog::Bouncer::Security.new(&block)
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
        groups << LocalGroup.new(name, description, self, &block)
      end

      def sync
        groups.each do |group|
          group.sync
        end
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

      def to_ip_permissions
        permissions = []

        sources.each do |source|
          source.protocols.each do |type, protocol|
            protocol.each do |p|
              permission = permissions.find { |permission| permission["IpProtocol"] == type.to_s && permission["FromPort"] == p.from && permission["ToPort"] == p.to }
              unless permission
                permission = { "Groups" => [], "IpRanges" => [], "IpProtocol" => type.to_s, "FromPort" => p.from, "ToPort" => p.to }
                permissions << permission
              end
              if source.is_a?(Fog::Bouncer::Sources::CIDR)
                permission["IpRanges"] << { "CidrIp" => source.range }
              else
                permission["Groups"] << { "UserId" => source.user_id, "GroupName" => source.name }
              end
            end
          end
        end

        permissions
      end
    end

    class LocalGroup < Group
      def remote
        @remote ||= RemoteGroup.for(name, security)
      end

      def group_id
        remote.fog.group_id if remote
      end

      def sync
        create_missing_remote
        synchronize_sources
      end

      private

      def create_missing_remote
        return if remote

        Fog::Bouncer.fog.security_groups.create(:name => name, :description => description)

        remote = RemoteGroup.for(name, security)
      end

      def synchronize_sources
        remote.fog.connection.authorize_security_group_ingress(name, "IpPermissions" => to_ip_permissions)
      end
    end

    class RemoteGroup < Group
      attr_accessor :fog

      def self.for(name, security)
        if group = Fog::Bouncer.fog.security_groups.get(name)
          remote = new(name, group.description, security) do
            group.ip_permissions.each do |permission|
              sources = []
              sources = sources | permission["groups"].collect { |group| "#{group["groupName"]}@#{group["userId"]}" }
              sources = sources | permission["ipRanges"].collect { |range| range["cidrIp"] }
              sources.each do |s|
                source s do
                  case permission["ipProtocol"]
                  when "icmp"
                    icmp Range.new(permission["fromPort"], permission["toPort"])
                  when "tcp"
                    tcp Range.new(permission["fromPort"], permission["toPort"])
                  when "udp"
                    udp Range.new(permission["fromPort"], permission["toPort"])
                  end
                end
              end
            end
          end
          remote.fog = group
          remote
        end
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

        def sync
          protocols.each do |type, rules|
            rule.each do |rule|

            end
          end
        end
      end

      class Group < Fog::Bouncer::Source
        attr_reader :name, :user_alias, :user_id

        def initialize(source, group, &block)
          super
          case source
          when /^(.+)@(.+)$/
            @name = $1
            id_or_alias = $2
            if id_or_alias[/^\d+$/]
              @user_id = id_or_alias
              if account = group.security.accounts.find { |key, id| id == @user_id }
                @user_alias = account[0]
              end
            else
              @user_alias = id_or_alias
            end
          when /^@(.+)$/
            @user_alias = $1
          else
            @name = source
          end
        end

        def user_id
          @user_id ||= group.security.accounts[user_alias]
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
