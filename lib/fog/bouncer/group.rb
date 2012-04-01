module Fog
  module Bouncer
    class Group
      attr_reader :name, :description, :security
      attr_accessor :local, :remote

      def self.log(data, &block)
        Fog::Bouncer.log({ group: true }.merge(data), &block)
      end

      def log(data, &block)
        self.class.log({ name: name }.merge(data), &block)
      end

      def initialize(name, description, security, &block)
        @name = name
        @description = description
        @security = security
        if block_given?
          @local = true
          instance_eval(&block)
        end
      end

      def extras
        Fog::Bouncer::SourcesProxy.new(sources.select { |source| !source.local? || source.extras? })
      end

      def extras?
        extras.any?
      end

      def local?
        local
      end

      def missing
        Fog::Bouncer::SourcesProxy.new(sources.select { |source| !source.remote? || source.missing? })
      end

      def missing?
        missing.any?
      end

      def from_ip_permissions(ip_permissions)
        ip_permissions.each do |permission|
          remote_sources = []
          remote_sources = remote_sources | permission["groups"].collect { |group| "#{group["groupName"]}@#{group["userId"]}" }
          remote_sources = remote_sources | permission["ipRanges"].collect { |range| range["cidrIp"] }
          remote_sources.each do |s|
            source = sources.find { |source| source.source == s }
            source = Sources.for(s, self) if source.nil?
            source.remote = true
            source.from_ip_protocol(permission["ipProtocol"], permission["fromPort"], permission["toPort"])
          end
        end
      end

      def remote?
        !remote.nil?
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
        "<#{self.class.name} @name=#{name.inspect} @description=#{description.inspect} @sources=#{sources.inspect}>"
      end

      def sync
        log(sync: true) do
          create_missing_remote
          synchronize_sources
        end
      end

      def destroy_extras
        if extras?
          log(destroy_extras: true) do
            extra.log(removing: true)
            remote.connection.revoke_security_group_ingress(name, "IpPermissions" => extras.to_ip_permissions(true))
            extras.each { |e| e.remote = true; e.extras.each { |p| p.remote = true } }
            remote.reload
          end
        end
        @extras = nil
      end

      def create_missing
        if missing?
          create_missing_remote

          log(create_missing: true) do
            missing.log(creating: true)
            remote.connection.authorize_security_group_ingress(name, "IpPermissions" => missing.to_ip_permissions)
            missing.each { |m| m.remote = true; m.missing.each { |p| p.remote = true } }
            remote.reload
          end
        end
        @missing = nil
      end

      def create_missing_remote
        unless remote
          log(create_missing_remote: true) do
            Fog::Bouncer.fog.security_groups.create(:name => name, :description => description)
            remote = true
          end
        end
      end

      def synchronize_sources
        log(synchronize_sources: true) do
          destroy_extras
          create_missing
        end
      end

      def destroy
        revoke
        if remote? && name != "default"
          log(destroy: true) do
            remote.destroy
            remote = nil
          end
        end
      end

      def revoke
        if remote? && sources.any?
          log(revoke: true) do
            sources.log(revoking: true)
            fog.connection.revoke_security_group_ingress(name, "IpPermissions" => sources.to_ip_permissions)
          end
        end
      end

      private

      def source(source, &block)
        if existing = sources.find { |s| s.source == source }
          existing.instance_eval(&block)
        else
          sources << Sources.for(source, self, &block)
        end
      end
    end
  end
end
