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

      def clone(sources)
        clone = self.class.new(name, description, security)
        clone.sources = sources
        clone
      end

      def sources
        @sources ||= SourcesProxy.new
      end

      def sources=(sources)
        @sources = sources
      end

      def to_ip_permissions
        sources.to_ip_permissions
      end

      def ==(other)
        name == other.name &&
        description == other.description
      end

      def inspect
        "<#{self.class.name} @name=#{name} @description=#{description} @sources=#{sources.inspect}>"
      end

      def source(source, &block)
        if existing = sources.find { |s| s.source == source }
          existing.instance_eval(&block)
        else
          sources << Sources.for(source, self, &block)
        end
      end
    end

    class LocalGroup < Group
      def extras
        extras = SourcesProxy.new

        local_sources = sources.collect { |source| source.source }

        remote.sources.each do |source|
          extras << source unless local_sources.include?(source.source)
        end if remote

        sources.each do |source|
          if source.remote && source.extras?
            extras << source.clone(source.extras)
          end
        end

        extras
      end

      def extras?
        extras.any?
      end

      def missing
        missing = SourcesProxy.new

        sources.each do |source|
          if source.remote && source.missing?
            missing << source.clone(source.missing)
          elsif !source.remote
            missing << source
          end
        end

        missing
      end

      def missing?
        missing.any?
      end

      def group_id
        remote.fog.group_id if remote
      end

      def remote
        RemoteGroup.for(name, security)
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
        remote.reload
      end
    end

    class RemoteGroup < Group
      attr_accessor :fog

      def self.for(name, security)
        remote_group = security.remote_groups.find { |group| group.name == name }

        if !remote_group && group = Fog::Bouncer.fog.security_groups.get(name)
          remote_group = from(group, security)
          security.remote_groups << remote_group
        end

        remote_group
      end

      def self.from(group, security)
        remote = new(group.name, group.description, security)
        remote.from(group)
        remote
      end

      def from(group)
        @sources = SourcesProxy.new
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
        end if group.ip_permissions
        @fog = group
      end

      def reload
        from(fog.reload)
      end
    end
  end
end
