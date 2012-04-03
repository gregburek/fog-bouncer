module Fog
  module Bouncer
    module IPPermissions
      def self.from(protocols, options = {})
        permissions = []

        protocols.each do |protocol|
          next if (options[:remote_only] && protocol.local?) ||
                  (options[:local_only] && protocol.remote?)

          source = protocol.source
          permission = permissions.find { |permission| permission["IpProtocol"] == protocol.type && permission["FromPort"] == protocol.from && permission["ToPort"] == protocol.to }

          if permission.nil?
            permission = { "Groups" => [], "IpRanges" => [], "IpProtocol" => protocol.type, "FromPort" => protocol.from, "ToPort" => protocol.to }
            permissions << permission
          end

          if source.is_a?(Fog::Bouncer::Sources::CIDR)
            permission["IpRanges"] << { "CidrIp" => source.range }
          else
            permission["Groups"] << { "UserId" => source.user_id, "GroupName" => source.name }
          end
        end

        permissions
      end

      def self.to(group, permissions)
        permissions.each do |permission|
          remote_sources = []
          remote_sources = remote_sources | permission["groups"].collect { |group| "#{group["groupName"]}@#{group["userId"]}" }
          remote_sources = remote_sources | permission["ipRanges"].collect { |range| range["cidrIp"] }
          remote_sources.each do |remote_source|
            source = group.sources.find { |s| s.match(remote_source) }

            if source.nil?
              source = Sources.for(remote_source, group)
              group.sources << source
            end

            source.remote = true

            protocol = source.add_protocol(permission["ipProtocol"], Range.new(permission["fromPort"], permission["toPort"]))
            protocol.remote = true
          end
        end
      end
    end
  end
end
