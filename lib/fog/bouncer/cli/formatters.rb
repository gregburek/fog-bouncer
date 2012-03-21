module Fog
  module Bouncer
    module CLI
      class Formatter
      end

      module Formatters
        class Diff < Formatter
          def self.format(doorlist)
            diff = "Extras:"
            doorlist.extras.each do |extra|
              diff << " \n#{extra.name}:"
              extra.sources.each do |source|
                diff << "  \n#{source.source}:"
                source.protocols.each do |protocol|
                  diff << "   \n#{protocol.type} #{protocol.from} #{protocol.to}"
                end
              end
            end

            diff << "\n\nMissing:"
            doorlist.missing.each do |missing|
              diff << " \n#{missing.name}:"
              missing.sources.each do |source|
                diff << "  \n#{source.source}:"
                source.protocols.each do |protocol|
                  diff << "   \n#{protocol.type} #{protocol.from} #{protocol.to}"
                end
              end
            end

            diff
          end
        end

        class JSON < Formatter
        end
      end
    end
  end
end
