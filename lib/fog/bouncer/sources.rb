require "fog/bouncer/source"

module Fog
  module Bouncer
    class SourcesProxy < Array
      def log(data)
        each do |source|
          source.protocols.each do |protocol|
            Fog::Bouncer.log(data.merge(protocol.to_log))
          end
        end
      end

      def to_ip_permissions
        permissions = []

        each do |source|
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
  end
end
