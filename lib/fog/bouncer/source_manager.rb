module Fog
  module Bouncer
    class SourceManager
      def self.log(data, &block)
        Fog::Bouncer.log({source_manager: true}.merge(data), &block)
      end

      def log(data, &block)
        self.class.log({group_name: @group.name}.merge(data), &block)
      end

      def initialize(group)
        @group = group
      end

      def synchronize
        log(synchronize: true) do
          create_missing_source_permissions
          remove_extra_source_permissions
          @group.sources.each { |s| s.remote = true } unless Fog::Bouncer.pretending?
        end
      end

      private

      def create_missing_source_permissions
        if missing_source_permissions.any?
          @group.remote.connection.authorize_security_group_ingress(@group.name, "IpPermissions" => IPPermissions.from(missing_source_permissions, :local_only => true)) unless Fog::Bouncer.pretending?
          missing_source_permissions.each do |protocol|
            log({authorized: true}.merge(protocol.to_log))
            protocol.remote = true unless Fog::Bouncer.pretending?
          end
        end
      end

      def missing_source_permissions
        @group.sources.map do |source|
          source.protocols.select { |p| p.local? && !p.remote? }
        end.flatten.compact
      end

      def remove_extra_source_permissions
        if extra_source_permissions.any?
          @group.remote.connection.revoke_security_group_ingress(@group.name, "IpPermissions" => IPPermissions.from(extra_source_permissions, :remote_only => true)) unless Fog::Bouncer.pretending?
          extra_source_permissions.each do |protocol|
            log({revoked: true}.merge(protocol.to_log))
            protocol.source.protocols.delete_if { |p| p == protocol } unless Fog::Bouncer.pretending?
          end
        end
      end

      def extra_source_permissions
        @group.sources.map do |source|
          source.protocols.select { |p| !p.local? && p.remote? }
        end.flatten.compact
      end
    end
  end
end
