module Fog
  module Bouncer
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

      def to_ip_permissions
        permissions = []

        sources.each do |source|
          source.protocols.each do |protocol|
            permission = permissions.find { |permission| permission["IpProtocol"] == protocol.type && permission["FromPort"] == protocol.from && permission["ToPort"] == protocol.to }
            unless permission
              permission = { "Groups" => [], "IpRanges" => [], "IpProtocol" => protocol.type, "FromPort" => protocol.from, "ToPort" => protocol.to }
              permissions << permission
            end
            if source.is_a?(Fog::Bouncer::Sources::CIDR)
              permission["IpRanges"] << { "CidrIp" => source.range }
            else
              permission["Groups"] << { "UserId" => source.user_id, "GroupName" => source.name }
            end
          end
        end

        permissions
      end

      private

      def source(source, &block)
        sources << Sources.for(source, self, &block)
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
  end
end
