require "rails/all"

module DynamicProcessorApp
  class Application < Rails::Application
    config.load_defaults 8.0
    config.active_storage.variant_processor = ENV.fetch("VARIANT_PROCESSOR").to_sym
  end
end
