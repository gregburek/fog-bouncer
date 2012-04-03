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
    end
  end
end
